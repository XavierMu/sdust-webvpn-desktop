/* SDUST WebVPN 本地代理 · 控制面板 */
const invoke = window.__TAURI__?.core?.invoke;
const $ = (id) => document.getElementById(id);

/* 名单输入框：用户改了就不要被轮询刷新覆盖（否则打字会被 2 秒一次的状态刷新吃掉） */
const dirtyFields = new Set();
/* 保存/撤销后强制与服务端对齐一次（否则"值不同=dirty"的判定会挡住回填） */
let syncForced = false;
function forceSync() {
  syncForced = true;
}
function syncDirtyUI() {
  const any = dirtyFields.size > 0;
  $('dirty-hint').hidden = !any;
  $('btn-reset').hidden = !any;
}
for (const id of ['in-proxy-hosts', 'in-direct-hosts']) {
  const el = $(id);
  const mark = () => {
    dirtyFields.add(id);
    syncDirtyUI();
  };
  el.addEventListener('input', mark);
  el.addEventListener('change', mark);
}

/* 账号框：用户打过字就不要被 2 秒一次的刷新回填覆盖 */
let userTouched = false;
$('in-user').addEventListener('input', () => {
  userTouched = true;
});

/** 统一的错误取字（Tauri 命令失败时抛的是字符串，接口失败抛的是 Error） */
function errText(e) {
  if (!e) return '未知错误';
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

let lastStatus = null;
let online = false;
let starting = false;
/** 核心没能启动的原因（核心现在随程序自动启动，起不来只在顶部横幅里说一声） */
let coreError = '';
let logCursor = -1;

/* ---------- 主题 ---------- */
const THEMES = ['auto', 'light', 'dark'];
const THEME_LABEL = { auto: '自动', light: '浅色', dark: '深色' };
const mqLight = window.matchMedia('(prefers-color-scheme: light)');

function themePref() {
  const t = localStorage.getItem('vpn-theme');
  return THEMES.includes(t) ? t : 'auto';
}

function applyTheme(pref) {
  const resolved = pref === 'auto' ? (mqLight.matches ? 'light' : 'dark') : pref;
  document.documentElement.dataset.theme = resolved;
  $('btn-theme').textContent = resolved === 'light' ? '☀' : '☾';
  $('btn-theme').title = `主题：${THEME_LABEL[pref]}（点击切换）`;
}

$('btn-theme').addEventListener('click', () => {
  const next = THEMES[(THEMES.indexOf(themePref()) + 1) % THEMES.length];
  localStorage.setItem('vpn-theme', next);
  applyTheme(next);
});
mqLight.addEventListener('change', () => applyTheme(themePref()));

/* ---------- 控制接口 ---------- */
async function api(path, body) {
  const res = await fetch(`http://127.0.0.1:8897${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function pill(el, kind, text) {
  el.className = `pill ${kind}`;
  el.textContent = text;
}

function tag(el, kind, text) {
  el.className = kind ? `tag ${kind}` : 'tag';
  el.textContent = text;
}

/* ---------- 连接状态机 ----------
   界面上每个灯、每句提示、每个按钮文案都从这一个状态派生，避免多处各自判定互相打架：
     offline       控制接口没通（内核没起来 / 端口被占 / 另一个副本在跑）
     unconfigured  本机还没有账号密码 —— 核心会一直待命，点「开启系统代理」时先带人去填账号
     logged-out    有账号，但当前没有会话（核心待命）
     ready         有会话，但核心还没起来（正常情况下一登录就会自动起来）
     running       核心在跑，且会话确认可用
     degraded      核心在跑，但会话已经失效（请求会被踢回登录页）
   "会话可用"用的是服务端给的 sessionOk（最近一次真实请求确实走通了），
   而不是"罐里有票据"——票据可能过期，也可能是登录失败留下的匿名票据。 */
function connState(st) {
  if (!st || !online) return 'offline';
  const s = st.session || {};
  if (st.proxy?.running) return s.sessionOk ? 'running' : 'degraded';
  if (!s.hasCreds) return 'unconfigured';
  if (!s.loggedIn) return 'logged-out';
  return 'ready';
}

/* ---------- 渲染 ---------- */
function render(st) {
  lastStatus = st;
  const s = st.session || {};
  const p = st.proxy || {};
  const sys = st.systemProxy || {};
  const ca = st.ca || {};
  const cfg = st.config || {};
  const running = Boolean(p.running);
  const pacMode = Boolean(sys.autoConfigUrl && String(sys.autoConfigUrl).includes('/pac'));
  // 系统代理不只"开没开"：别的代理软件（翻墙软件的系统代理模式）写的是同一个开关，
  // 得看现在到底是不是我们接管的，否则会把别人的代理显示成"已接管"。
  const sysOwner = String(sys.owner || '');
  const sysOurs = sysOwner === 'ours';
  const port = p.port || cfg.proxyPort || 8899;

  const state = connState(st);
  // 最近一次登录尝试的失败记录（成功登录后由服务端清掉）。它和"当前有没有会话"是两件事：
  // 用户重新填的密码没生效时，旧会话可能还在正常工作，照样要把失败说出来。
  // 例外：「没有可用的账号密码」不算登录失败 —— 那是"还没开始配置"，不该红着脸报警。
  const loginErr = noCredsError(s.lastError) ? '' : s.lastError ? String(s.lastError) : '';
  const credsSaved = Boolean(s.hasCreds);
  const username = s.username ? String(s.username) : '';
  const shortTicket = s.ticket ? `${String(s.ticket).slice(0, 4)}…` : '';

  pill($('core-pill'), running ? 'ok' : coreError ? 'bad' : 'warn',
    running ? '核心运行中' : coreError ? '核心没起来' : '核心待命');
  let loginKind = 'warn';
  let loginText = '未登录';
  if (loginErr) {
    loginKind = s.loggedIn ? 'warn' : 'bad';
    loginText = s.loggedIn ? '仍用上次登录' : '登录失败';
  } else if (s.loggedIn) {
    loginKind = 'ok';
    loginText = '已登录';
  }
  pill($('login-pill'), loginKind, loginText);
  if (sysOurs && !running) {
    // 指向本程序、但核心没跑：多半是上次没走正常收尾（被强杀），系统代理会指向一个死端口
    pill($('proxy-pill'), 'warn', '系统代理：残留未还原');
  } else if (sysOurs) {
    pill($('proxy-pill'), 'ok', `系统代理：${pacMode ? 'PAC' : '全局'} · 已接管`);
  } else if (sysOwner === 'other') {
    pill($('proxy-pill'), 'bad', '系统代理：被占用');
  } else {
    pill($('proxy-pill'), 'grey', '系统代理：未接管');
  }
  $('proxy-pill').title =
    sysOwner === 'other'
      ? `系统代理现在指向 ${sys.ownerDetail || '其它程序'}，不是本程序`
      : sysOurs && !running
        ? '系统代理还指着本程序，但核心没在跑 —— 点「关闭系统代理」还原'
        : sysOurs
          ? '系统代理已指向本程序（本机代理 / PAC）'
          : '系统代理没有指向本程序';

  const degraded = state === 'degraded';
  const coreErr = running ? '' : coreError;
  if (degraded) {
    tag($('conn-tag'), 'bad', running ? `127.0.0.1:${port} · 会话失效` : '会话失效');
  } else {
    tag($('conn-tag'), coreErr ? 'bad' : running ? 'ok' : 'warn',
      running ? `127.0.0.1:${port}` : coreErr ? '核心没起来' : '核心待命');
  }
  // 顶部状态条：①运行中会话失效 ②核心没能启动 —— 两种都在这里给结果和出路
  const bannerMsg = degraded
    ? loginErr
      ? `自动重登没有成功：${loginErr}`
      : '连接已经不可用，正在尝试自动重登…'
    : coreErr
      ? `核心没能启动：${coreErr}`
      : '';
  $('state-banner').hidden = !bannerMsg;
  if (bannerMsg) {
    $('state-banner').querySelector('b').textContent = degraded ? '会话已失效' : '核心没起来';
    $('state-banner-msg').textContent = bannerMsg;
    $('state-banner-note').textContent = degraded
      ? '代理还在运行，但校内请求会被踢回登录页。'
      : '常见原因是端口被占用或另一个副本占着 8897；详细原因看右侧日志。';
    $('state-banner-retry').hidden = false;
    $('state-banner-retry').textContent = degraded ? '重新登录' : '重试';
  }
  // 后台自动重登停了（连续失败到上限）→ 提示一次，别让它默默不干活
  if (s.reloginPaused) {
    showNotice(
      'relogin-paused',
      `自动重登已暂停：连续 ${s.keepaliveFails || 3} 次登录/保活失败，后台不会再自动重试了。` +
        '改好密码后点「保存并登录」，或重启一次程序。'
    );
  }

  // 存凭据不依赖代理是否运行（控制接口一直在跑）：核心待命时也能先登录
  // 核心没跑、但系统代理还残留着本程序的设置时，也要能点「关闭系统代理」还原
  // 这个按钮是"要动网络设置"的唯一入口，核心没跑也可能是没账号（待命），不能因此禁掉它
  $('btn-sysproxy').disabled = false;
  // 以"是不是我们接管的"为准：被别人占用时按钮应该是「开启系统代理」（点一下抢回来），
  // 而不是「关闭系统代理」（那会把别人的设置当成我们的去还原）。
  $('btn-sysproxy').textContent = sysOurs ? '关闭系统代理 ↺' : '开启系统代理';
  $('btn-sysproxy').className = sysOurs ? 'off' : 'activate';

  if (document.activeElement !== $('in-port')) $('in-port').value = cfg.proxyPort ?? 8899;
  // 名单：用户正在编辑（input 事件已标脏）就不覆盖，其余情况一律以服务端为准。
  // 不能拿"值不同"当脏判据：首次渲染时输入框还是空的，会被误判成用户改动。
  for (const [id, arr] of [
    ['in-proxy-hosts', cfg.proxyHosts],
    ['in-direct-hosts', cfg.directHosts],
  ]) {
    const el = $(id);
    if (!syncForced && dirtyFields.has(id)) continue;
    const next = (arr || []).join('\n');
    if (el.value !== next) {
      el.value = next;
      el.scrollTop = 0;
    }
  }
  if (syncForced) {
    syncForced = false;
    dirtyFields.clear();
    syncDirtyUI();
  }

  if (document.activeElement !== $('in-mode')) {
    $('in-mode').value = pacMode ? 'pac' : cfg.sysproxyMode || 'pac';
  }
  // 模式与名单始终可改：核心停止时改的是配置，下次启动即生效
  $('in-mode').disabled = false;
  // 全局模式忽略名单：把输入框置灰并说明，免得以为改了会生效
  const globalMode = (cfg.sysproxyMode || 'global') === 'global';
  for (const id of ['in-proxy-hosts', 'in-direct-hosts']) {
    const el = $(id);
    el.disabled = false;
    el.classList.toggle('dim', globalMode);
  }
  tag($('rules-mode-badge'), globalMode ? 'warn' : 'ok', globalMode ? '全局 · 名单不生效' : '按名单分流');
  $('rules-mode-note').textContent = globalMode
    ? '全局模式下名单不生效（要按名单分流请切到 PAC）'
    : '黑名单优先，未命中直连';
  $('in-envproxy').checked = Boolean(cfg.envProxy);
  $('in-envproxy').disabled = !running;
  $('btn-save').disabled = false;

  tag($('acct-tag'), loginKind, loginErr ? loginText : s.loggedIn ? `票据 ${shortTicket}` : '未登录');
  // A1/A5：把"当前是哪个账号、会话到底能不能用"直接写在卡片上
  $('acct-who').textContent = !username
    ? '本机还没有保存账号'
    : s.loggedIn
      ? `本机账号 ${username} · ${s.sessionOk ? '会话可用' : '会话待验证'}` +
        (loginErr ? '（仍在用上一次登录成功的那份）' : '')
      : `本机账号 ${username} · 未登录`;
  $('btn-logout').disabled = !(s.loggedIn || credsSaved);
  $('btn-logout').title = credsSaved
    ? '删掉本机保存的账号密码和当前登录态，下次要重新填'
    : '清掉当前登录态（本机没有保存账号密码）';
  // A1：账号框用当前账号预填（用户没动过、框还是空的时候才填，不干扰打字）
  if (!userTouched && !$('in-user').value && username) $('in-user').value = username;
  // 登录失败：卡片里留一条常驻红色横幅，并单独弹一次说明原因的窗口
  $('login-error-banner').hidden = !loginErr;
  $('login-error-banner-msg').textContent = loginErr;
  $('login-error-banner-note').textContent = !loginErr
    ? ''
    : (credsSaved
        ? '这次填的凭据没有被保存，本机保存的仍是上一次能登录成功的那份。'
        : '这次填的凭据没有被保存。') +
      (s.loggedIn && credsSaved
        ? '当前会话还在用旧的那份，可以照常上网；改好密码后再点一次「保存并登录」。'
        : '改好之后在下面再点一次「保存并登录」。');
  // 启动时不再自动弹「登录失败」窗口（只在用户点「开启系统代理」/「保存并登录」时才弹），
  // 这里只把「已经弹过」的标记清掉，好让下一次主动操作还能弹出来。
  if (!loginErr) loginFailShown = '';

  tag($('ca-tag'), ca.installed ? 'ok' : 'warn', ca.installed ? '已安装' : '未安装');
  $('btn-ca').textContent = ca.installed ? '卸载' : '安装';
  $('btn-ca').className = ca.installed ? 'danger' : '';
  // 存凭据不依赖核心是否在跑（控制接口一直在跑）：核心待命时也能先登录
  $('btn-save-creds').disabled = false;
  $('btn-check').disabled = false;
  $('ca-hint').textContent = ca.installed
    ? '已信任，HTTPS 可透明转发'
    : 'HTTPS 透明转发需要本机信任此证书（点安装，Windows 会弹一次确认）';
  if (ca.path) {
    $('ca-hint').title = ca.path;
  }

  const stats = p.stats || {};
  $('st-school').textContent = stats.school ?? 0;
  $('st-direct').textContent = stats.direct ?? 0;
  $('st-rewrite').textContent = stats.rewrites ?? 0;
  $('st-error').textContent = stats.errors ?? 0;

  if (!running) {
    $('sysproxy-hint').textContent = coreErr
      ? `核心没能启动：${coreErr}`
      : state === 'unconfigured'
        ? '核心待命 · 填好账号密码登录后，点这里开启系统代理'
        : '核心待命 · 点「开启系统代理」开始用';
  } else if (sysOurs && pacMode) {
    $('sysproxy-hint').textContent = `已接管 · PAC · 127.0.0.1:${port}`;
  } else if (sysOurs) {
    $('sysproxy-hint').textContent = `已接管 · 全局 · 127.0.0.1:${port} · 全部走学校出口`;
  } else if (sysOwner === 'other') {
    $('sysproxy-hint').textContent = `系统代理正被其它程序占用（${sys.ownerDetail || '未知'}）—— 点「开启系统代理」抢回来`;
  } else {
    $('sysproxy-hint').textContent = '系统代理未接管';
  }

  if (cfg.dataRoot) {
    $('data-root').textContent = cfg.dataRoot || '';
    $('data-root').title = cfg.dataRoot;
  }
  $('app-version').textContent = cfg.version ? 'v' + cfg.version : '—';

  renderOnline(st.online || {});
  renderPortal();
}

/* ---------- 在线规则 ---------- */
/** 多行地址框 → 地址数组（一行一个，去掉空行） */
function readOnlineUrls() {
  return $('in-online-url')
    .value.split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** 只留主机名，状态行里显示「实际走的是哪个镜像」用 */
function urlHost(u) {
  try {
    return new URL(u).host;
  } catch {
    return String(u);
  }
}

function renderOnline(online) {
  // 地址框：用户正在打字就别抢
  if (document.activeElement !== $('in-online-url')) {
    const text = (Array.isArray(online.urls) ? online.urls : []).join('\n');
    if ($('in-online-url').value !== text) $('in-online-url').value = text;
  }
  const src = online.source === 'local' ? 'local' : 'online';
  $('src-online').checked = src === 'online';
  $('src-local').checked = src === 'local';
  if (document.activeElement !== $('in-online-interval')) {
    const hours = Number(online.intervalHours ?? 24);
    const sel = $('in-online-interval');
    // 自定义值（比如手动写进配置的 12）也如实显示
    if ([...sel.options].some((o) => o.value === String(hours))) sel.value = String(hours);
  }

  const urls = (Array.isArray(online.urls) ? online.urls : []).filter((u) => String(u).trim());
  const configured = urls.length > 0;
  const active = Boolean(online.active);
  const count = Number(online.count || 0);
  const remoteTotal = Number(online.remoteProxy || 0) + Number(online.remoteDirect || 0);
  let kind = 'warn';
  let text = '未启用';
  if (online.error) {
    kind = 'bad';
    text = '同步失败';
  } else if (configured && active && remoteTotal > 0) {
    kind = 'ok';
    text = '在线 + 本地';
  } else if (configured && active) {
    kind = 'warn';
    text = '待同步';
  } else if (configured && src === 'local') {
    kind = 'warn';
    text = '只用本地';
  }
  tag($('online-badge'), kind, text);
  tag($('online-modal-badge'), kind, text);

  // 弹窗里空间够，写全；卡片右下角只留一眼能看完的（完整信息挂 title）
  const bits = [];
  if (remoteTotal > 0) bits.push(`在线 ${remoteTotal} 条（白 ${online.remoteProxy || 0} / 黑 ${online.remoteDirect || 0}）`);
  if (online.remoteName) bits.push(String(online.remoteName));
  if (online.remoteUpdated) bits.push(`规则更新 ${online.remoteUpdated}`);
  // 配了多个镜像才值得说「这次走的是哪个」
  if (urls.length > 1 && online.lastUrl) bits.push(`本次走 ${urlHost(online.lastUrl)}`);
  if (online.syncedAt) bits.push(`同步于 ${fmtStamp(Number(online.syncedAt))}`);
  if (online.error) bits.push(String(online.error));
  const full = bits.join(' · ');

  const cardBits = [];
  if (remoteTotal > 0) cardBits.push(`在线 ${remoteTotal} 条`);
  if (urls.length > 1 && online.lastUrl) cardBits.push(`走 ${urlHost(online.lastUrl)}`);
  if (online.syncedAt) cardBits.push(`${fmtStamp(Number(online.syncedAt)).slice(5)} 同步`);
  $('online-meta').textContent = cardBits.join(' · ');
  $('online-meta').title = full;
  $('online-modal-meta').textContent = full;
  $('btn-online-clear').hidden = !(remoteTotal > 0 || count > 0);
  $('btn-online-sync').disabled = !configured;
  $('btn-online-force').disabled = !configured;
}

/* ---------- 校内导航（内置站点清单，用各站点原始地址） ---------- */
/* 站点数据在 sites.js 的 PORTAL_SITES 里写死，这里只负责画和搜 */
let portalSites = (typeof PORTAL_SITES === 'undefined') ? [] : PORTAL_SITES.slice();

function renderPortal() {
  tag($('portal-badge'), 'ok', `${portalSites.length} 个站点`);
  drawPortal();
}

/* 站点列表按搜索词过滤后重画（数据或搜索词变了都走这里） */
function drawPortal() {
  const box = $('portal-list');
  const kw = $('in-portal-search').value.trim().toLowerCase();
  const list = portalSites.filter((s) => {
    if (!kw) return true;
    return `${s.name || ''} ${s.url || ''}`.toLowerCase().includes(kw);
  });
  box.textContent = '';
  if (!list.length) {
    const p = document.createElement('p');
    p.className = 'muted small empty-hint';
    p.textContent = portalSites.length ? '没有匹配的站点。' : '站点清单是空的。';
    box.appendChild(p);
    return;
  }
  for (const s of list) {
    const item = document.createElement('div');
    item.className = 'portal-item';
    const main = document.createElement('div');
    main.className = 'p-main';
    const name = document.createElement('span');
    name.className = 'p-name';
    name.textContent = s.name || '(未命名)';
    name.title = s.name || '';
    const host = document.createElement('span');
    host.className = 'p-host';
    host.textContent = hostOf(s.url);
    host.title = s.url || '';
    main.append(name, host);
    const acts = document.createElement('div');
    acts.className = 'p-actions';
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'ghost small-btn';
    copy.textContent = '复制';
    copy.title = `复制 ${s.url}`;
    copy.addEventListener('click', async () => {
      const ok = await copyText(s.url || '');
      showNotice(ok ? 'copied' : 'copy-fail',
        ok ? `已复制：${s.url}` : `复制失败，手动选中这行：${s.url}`);
    });
    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'small-btn';
    open.textContent = '打开';
    open.title = `用默认浏览器打开 ${s.url}`;
    open.addEventListener('click', () => openSite(s));
    acts.append(copy, open);
    item.append(main, acts);
    box.appendChild(item);
  }
}

/* 从 url 里取出域名部分（小字显示用） */
function hostOf(url) {
  try {
    return new URL(url).host || String(url || '');
  } catch {
    return String(url || '').replace(/^https?:\/\//, '').split('/')[0];
  }
}

async function copyText(text) {
  if (!text) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* 落到下面的兜底 */
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', 'readonly');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

async function openSite(site) {
  const url = site.url;
  if (!url) return;
  try {
    if (invoke) await invoke('open_external', { url });
    else window.open(url, '_blank');
  } catch (e) {
    showNotice('open-fail', `打开 ${site.name || url} 失败：${e}`);
  }
}


async function refresh() {
  try {
    const st = await api("/status");
    online = true;
    render(st);
  } catch {
    online = false;
    renderOffline();
  }
}

/* ---------- 日志 ---------- */
function appendLog(line) {
  const el = $('log');
  const t = String(line.t || '').replace('T', ' ').slice(11, 19);
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 8;
  el.textContent += `${t}  ${line.msg}\n`;
  // 只保留最近 400 行，避免文本无限增长
  const lines = el.textContent.split('\n');
  if (lines.length > 401) el.textContent = lines.slice(-401).join('\n');
  if (atBottom) el.scrollTop = el.scrollHeight;
}

async function pollLogs() {
  if (!online) return;
  try {
    const r = await api(`/logs?after=${logCursor}`);
    for (const line of r.lines || []) {
      appendLog(line);
      logCursor = line.i;
    }
    if (r.next !== undefined) logCursor = Math.max(logCursor, r.next);
  } catch {
    /* 忽略 */
  }
}

$('btn-log-clear').addEventListener('click', () => {
  $('log').textContent = '';
});

$('btn-log-copy').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('log').textContent);
    $('btn-log-copy').textContent = '已复制';
  } catch {
    $('btn-log-copy').textContent = '复制失败';
  }
  setTimeout(() => ($('btn-log-copy').textContent = '复制'), 1200);
});

/* ---------- 核心（随程序无感启动，界面上没有开关） ---------- */
// 核心只监听 127.0.0.1:8899，不碰系统代理；起不来也只在顶部横幅里说一声，不弹窗打断。
// 没账号 / 没登录时它本来就起不来，这不算故障：登录成功后由轮询或这里自动再拉一次。
async function ensureCore() {
  if (starting) return;
  starting = true;
  let startErr = '';
  try {
    if (invoke) await invoke('core_start');
    else await api('/proxy/start', {});
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 400));
      try {
        const st = await api('/status');
        online = true;
        render(st);
        if (st.proxy?.running) break;
      } catch {
        /* 继续等 */
      }
    }
  } catch (e) {
    startErr = errText(e);
    appendLog({ t: new Date().toISOString(), msg: `启动核心失败：${startErr}` });
  } finally {
    starting = false;
    await refresh();
    if (lastStatus?.proxy?.running) {
      coreError = '';
    } else {
      const s2 = lastStatus?.session || {};
      // 账号/登录问题不算"核心故障"：那种情况由登录灯 + 账号卡片里的红条说明，
      // 用户点「开启系统代理」时会得到明确提示。
      coreError =
        !s2.hasCreds || !s2.loggedIn
          ? ''
          : startErr || '核心没能在 16 秒内起来，详细原因见右侧日志。';
    }
  }
}

// 「开启系统代理」：已经是本程序接管 → 关掉还原；
// 否则先把没做的事问清楚（登录 → 核心 → 证书 → 冲突），再真正接管。
// 按钮不能因为"核心没跑"就禁掉 —— 没账号时核心本来就是待命状态，那正是用户要点它的时候。
$('btn-sysproxy').addEventListener('click', async () => {
  const sys = lastStatus?.systemProxy || {};
  const ours = String(sys.owner || '') === 'ours';
  if (ours) return guard(async () => {
    await api('/sysproxy', { mode: 'off' });
  });
  const s = lastStatus?.session || {};
  if (!s.loggedIn) {
    // 没登录就先说清楚为什么不往下走（这一步写系统代理，登录不上等于白接管）
    if (s.lastError && !noCredsError(s.lastError)) showLoginFailOnce(String(s.lastError));
    else promptLogin();
    return;
  }
  // 登录了但核心没跑（刚登录、或起得慢）：先把核心拉起来，别把系统代理指向一个空的端口
  if (!lastStatus?.proxy?.running) {
    if (coreError) return showStartFail(coreError);
    await ensureCore();
    if (!lastStatus?.proxy?.running) {
      return showStartFail(coreError || '核心还没起来，等两秒再点一次「开启系统代理」。');
    }
  }
  const takeover = () =>
    confirmTakeover(() =>
      guard(async () => {
        const mode = $('in-mode').value === 'pac' ? 'pac' : 'on';
        await api('/sysproxy', { mode, envProxy: $('in-envproxy').checked });
      })
    );
  // 证书没装：提示一次（「稍后」也不拦着接管），关掉提示后继续
  if (maybeShowCertPrompt()) {
    afterCertThen = takeover;
    return;
  }
  takeover();
});

// 「清除本机账号」：先确认一次 —— 这一步会删掉 .secrets 里保存的账号密码，
// 和「退出登录」不一样（那个只清会话）。
$('btn-logout').addEventListener('click', () => openModal($('forget-confirm')));
$('forget-confirm-cancel').addEventListener('click', () => closeModal($('forget-confirm')));
$('forget-confirm-x').addEventListener('click', () => closeModal($('forget-confirm')));
$('forget-confirm-ok').addEventListener('click', () =>
  guard(async () => {
    closeModal($('forget-confirm'));
    const r = await api('/logout', { forget: true });
    loginFailShown = '';
    $('login-error-banner').hidden = true;
    // 账号都清了，输入框里也别留着上一次的账号
    $('in-user').value = '';
    $('in-pass').value = '';
    userTouched = false;
    if (r.wasRunning) forceSync();
  })
);

// 顶部状态条上那颗按钮：会话失效时是「重新登录」，核心没起来时是「重试」。
$('state-banner-retry').addEventListener('click', async () => {
  const running = Boolean(lastStatus?.proxy?.running);
  const retryingCore = !running && Boolean(coreError);
  $('state-banner-retry').disabled = true;
  try {
    if (retryingCore) {
      await ensureCore();
      if (coreError) showStartFail(coreError);
    } else {
      await api('/login', {});
      loginFailShown = '';
      // 登录成功但核心没跑（比如刚才是没账号）→ 顺手把核心拉起来
      if (!lastStatus?.proxy?.running) await ensureCore();
    }
  } catch (e) {
    if (retryingCore) showStartFail(errText(e));
    else showLoginFail(errText(e));
  } finally {
    $('state-banner-retry').disabled = false;
    await refresh();
    await pollLogs();
  }
});

// 顶部「提示」条
$('notice-banner-x').addEventListener('click', () => {
  $('notice-banner').hidden = true;
});

/* ---------- 接管系统代理前的冲突确认 ---------- */
// 翻墙软件的「系统代理」模式和本程序抢同一个开关：检测到就先问一句，
// 不要默默把人家的设置顶掉（退出时会还原，但用户当场就断了网）。
let pendingTakeover = null;
function confirmTakeover(then) {
  const sys = lastStatus?.systemProxy || {};
  const who = String(sys.owner || '') === 'other' ? String(sys.ownerDetail || '其它程序') : '';
  if (!who) {
    then();
    return;
  }
  $('proxy-conflict-where').textContent = who;
  pendingTakeover = then;
  openModal($('proxy-conflict'));
}
function closeConflict() {
  pendingTakeover = null;
  closeModal($('proxy-conflict'));
}
$('proxy-conflict-cancel').addEventListener('click', closeConflict);
$('proxy-conflict-x').addEventListener('click', closeConflict);
$('proxy-conflict-ok').addEventListener('click', () => {
  const then = pendingTakeover;
  pendingTakeover = null;
  closeModal($('proxy-conflict'));
  if (then) then();
});

/* ---------- 状态检查（真的发请求体检，慢，所以只手动跑） ---------- */
const CHECK_MARK = { ok: '✓', warn: '!', bad: '✕' };
function renderDoctor(res) {
  const list = $('doctor-list');
  list.innerHTML = '';
  for (const it of res.items || []) {
    const level = it.level || 'ok';
    const row = document.createElement('div');
    row.className = `check-row ${level}`;
    const ico = document.createElement('span');
    ico.className = `check-ico ${level}`;
    ico.textContent = CHECK_MARK[level] || '·';
    const box = document.createElement('div');
    box.className = 'check-body';
    const name = document.createElement('b');
    name.textContent = it.label || '';
    const detail = document.createElement('span');
    detail.className = 'check-detail';
    detail.textContent = it.detail || '';
    box.append(name, detail);
    if (it.fix) {
      const fix = document.createElement('span');
      fix.className = 'check-fix';
      fix.textContent = `→ ${it.fix}`;
      box.append(fix);
    }
    row.append(ico, box);
    list.append(row);
  }
  const bad = Number(res.bad || 0);
  $('doctor-sum').textContent =
    bad === 0 ? '全部正常，状态灯已同步。' : `${bad} 项要注意（带 → 的是修法），状态灯已同步。`;
}
async function runDoctor() {
  const btn = $('btn-check');
  btn.disabled = true;
  $('doctor-list').innerHTML = '';
  $('doctor-sum').textContent = '正在检查…（要 3-8 秒）';
  openModal($('doctor'));
  try {
    renderDoctor(await api('/doctor', {}));
  } catch (e) {
    $('doctor-sum').textContent = `检查没跑完：${errText(e)}`;
  } finally {
    btn.disabled = false;
    // 回灌：状态灯 / 顶部横幅 / 日志立刻跟上（体检刚把服务端状态刷新过）
    await refresh();
    await pollLogs();
  }
}
$('btn-check').addEventListener('click', () => guard(runDoctor));
$('doctor-ok').addEventListener('click', () => closeModal($('doctor')));
$('doctor-x').addEventListener('click', () => closeModal($('doctor')));
$('doctor-again').addEventListener('click', () => guard(runDoctor));

$('in-envproxy').addEventListener('change', () =>
  guard(async () => {
    const enabled = $('in-envproxy').checked;
    await api('/envproxy', { enabled });
    await api('/config', { envProxy: enabled });
  })
);

/* ---------- 保存设置 ---------- */
$('btn-save').addEventListener('click', () =>
  guard(async () => {
    const proxyPort = Number($('in-port').value);
    if (!Number.isInteger(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
      throw new Error('代理端口要在 1024-65535 之间');
    }
    const proxyHosts = $('in-proxy-hosts')
      .value.split(/[\n,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const directHosts = $('in-direct-hosts')
      .value.split(/[\n,，;；]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    await api('/config', {
      proxyPort,
      proxyHosts,
      directHosts,
      sysproxyMode: $('in-mode').value === 'pac' ? 'pac' : 'global',
      envProxy: $('in-envproxy').checked,
    });
    forceSync();
    await refresh();
  })
);

$('btn-reset').addEventListener('click', () =>
  guard(async () => {
    forceSync();
    await refresh();
  })
);

/* ---------- 在线规则 ---------- */
/** 拉一次在线规则；force=true 忽略「远端比本地旧就拒绝」的保护 */
async function syncOnline(force) {
  const urls = readOnlineUrls();
  if (!urls.length) throw new Error('先填一个规则文件的地址（一行一个）');
  const bad = urls.find((u) => !/^https?:\/\//i.test(u));
  if (bad) throw new Error(`地址要以 http:// 或 https:// 开头：${bad}`);
  // 先把地址存进去，不然同步的还是旧地址
  await api('/config', { onlineUrls: urls, ruleSource: 'online' });
  const r = await api('/online', { action: 'sync', force: Boolean(force) });
  if (r.error) throw new Error(r.error);
  await refresh();
}

$('btn-online-sync').addEventListener('click', () =>
  guard(async () => {
    await syncOnline(false);
  })
);

$('btn-online-force').addEventListener('click', () =>
  guard(async () => {
    await syncOnline(true);
  })
);

$('btn-online-clear').addEventListener('click', () =>
  guard(async () => {
    await api('/online', { action: 'clear' });
    await refresh();
  })
);

for (const id of ['src-online', 'src-local']) {
  $(id).addEventListener('change', () =>
    guard(async () => {
      const source = $('src-online').checked ? 'online' : 'local';
      await api('/config', { ruleSource: source });
      await refresh();
    })
  );
}

$('in-online-interval').addEventListener('change', () =>
  guard(async () => {
    const hours = Number($('in-online-interval').value);
    await api('/config', { onlineIntervalHours: hours });
    await refresh();
  })
);

/* ---------- 校内导航 ---------- */
$('in-portal-search').addEventListener('input', () => drawPortal());

$('in-mode').addEventListener('change', () =>
  guard(async () => {
    const pac = $('in-mode').value === 'pac';
    tag($('rules-mode-badge'), pac ? 'ok' : 'warn', pac ? '按名单分流' : '全局 · 名单不生效');
    $('rules-mode-note').textContent = pac
      ? '黑名单优先，未命中直连'
      : '全局模式下名单不生效（要按名单分流请切到 PAC）';
    for (const id of ['in-proxy-hosts', 'in-direct-hosts'])
      $(id).classList.toggle('dim', !pac);
    // 选完立即生效，不必再点保存（名单里的未保存修改不受影响）
    await api('/config', { sysproxyMode: pac ? 'pac' : 'global' });
    await refresh();
  })
);

/* ---------- 账号 ---------- */
$('btn-save-creds').addEventListener('click', async () => {
  const username = $('in-user').value.trim();
  const password = $('in-pass').value;
  if (!username) return showLoginFail('还没有填账号（职工号 / 学号 / 邮箱 / 别名任一即可）。');
  if (!password) return showLoginFail('还没有填密码。');
  try {
    await api('/credentials', { username, password });
    $('in-pass').value = '';
    loginFailShown = '';
    $('login-error-banner').hidden = true;
    closeModal($('login-fail'));
    // 登录成功后核心马上就能用：核心随程序跑，这里顺手把它拉起来
    if (!lastStatus?.proxy?.running) await ensureCore();
  } catch (e) {
    // 立刻弹出来，不用等 2 秒轮询，也不用去翻日志
    showLoginFail(errText(e), true);
  } finally {
    await refresh();
    await pollLogs();
  }
});

/* ---------- 证书 ---------- */
$('btn-ca').addEventListener('click', () =>
  guard(async () => {
    const installed = Boolean(lastStatus?.ca?.installed);
    await api(installed ? '/ca/uninstall' : '/ca/install', {});
  })
);

/* ---------- 开机自启 ---------- */
async function initAutostart() {
  if (!invoke) {
    $('in-autostart').disabled = true;
    $('in-autostart').title = '仅在桌面应用内可用';
    return;
  }
  try {
    $('in-autostart').checked = await invoke('autostart_get');
  } catch {
    /* 读不到就保持未勾选 */
  }
}

$('in-autostart').addEventListener('change', async () => {
  const want = $('in-autostart').checked;
  try {
    const actual = await invoke('autostart_set', { enabled: want });
    $('in-autostart').checked = Boolean(actual);
    appendLog({
      t: new Date().toISOString(),
      msg: actual ? '已设置开机自启' : '已取消开机自启',
    });
  } catch (e) {
    $('in-autostart').checked = !want;
    appendLog({ t: new Date().toISOString(), msg: `开机自启设置失败：${e.message || e}` });
  }
});

/* ---------- 首次使用引导 / 根证书提示 / 登录提示 ---------- */
let guideChecked = false; // 每次运行只判断一次，避免 2 秒轮询重复弹窗
let caChecked = false;
let loginFailShown = ''; // 已经弹过的登录失败原因，避免 2 秒轮询反复弹
/** 证书提示是因「开启系统代理」弹出来的时候，关掉提示后接着做的事（继续接管系统代理） */
let afterCertThen = null;
const shownNotices = new Set(); // 顶部「提示」条只弹一次的类型

function anyModalOpen() {
  return Boolean(document.querySelector('.overlay:not([hidden])'));
}

function openModal(el) {
  el.hidden = false;
  document.body.classList.add('modal-open');
}

function closeModal(el) {
  el.hidden = true;
  if (!anyModalOpen()) document.body.classList.remove('modal-open');
}

/** 服务端 state/config.json 里的 guideSeen：只有明确为 false 才弹（老内核没这个字段就当作看过） */
function maybeShowFirstRun() {
  if (guideChecked) return;
  guideChecked = true;
  if (lastStatus?.config?.guideSeen !== false) return;
  openModal($('guide'));
}

/** 根证书没装、也没被「不再提示 / 稍后」压住时弹一次；返回这次是否弹了。
 *  只从「开启系统代理」的点击里调用 —— 也就是"第一次真正要动网络设置时"。 */
function maybeShowCertPrompt() {
  if (caChecked) return false;
  caChecked = true;
  if (lastStatus?.ca?.installed) return false;
  const cfg = lastStatus?.config || {};
  if (cfg.caPromptSeen === true) return false;
  // B4：点了「稍后」就 3 天内不再自动弹（不再是每次启动都弹一次）
  const until = Number(cfg.caPromptSnoozeUntil || 0);
  if (until > 0 && Date.now() / 1000 < until) return false;
  $('ca-prompt-err').hidden = true;
  openModal($('ca-prompt'));
  return true;
}

function markGuideSeen() {
  if (!$('guide-no-again').checked) return;
  const cfg = lastStatus?.config;
  if (!cfg || typeof cfg.guideSeen !== 'boolean') return;
  cfg.guideSeen = true;
  api('/config', { guideSeen: true }).catch(() => {});
}

/** 勾了「不再提示」→ 永久不弹；没勾（点了「稍后」或直接关掉）→ 3 天内不弹 */
function markCaPromptSeen() {
  const cfg = lastStatus?.config;
  if (!cfg) return;
  if ($('ca-prompt-no-again').checked) {
    cfg.caPromptSeen = true;
    api('/config', { caPromptSeen: true }).catch(() => {});
    return;
  }
  const until = Math.floor(Date.now() / 1000) + 3 * 86400;
  cfg.caPromptSnoozeUntil = until;
  api('/config', { caPromptSnoozeUntil: until }).catch(() => {});
}

/** 证书提示现在是「开启系统代理」流程里的一步：关掉（稍后 / 关窗 / 装完）后继续接管 */
function runAfterCert() {
  const then = afterCertThen;
  afterCertThen = null;
  if (then) then();
}

/** 顶部「提示」条：同一类型只提示一次，点「知道了」关掉 */
function showNotice(key, msg) {
  if (shownNotices.has(key)) return;
  shownNotices.add(key);
  $('notice-banner-msg').textContent = msg;
  $('notice-banner').hidden = false;
}

/** 老配置里那个「启动核心时自动接管系统代理」字段现在没有意义了：悄悄清掉，不弹任何提示。
    （接管改成手动点「开启系统代理」；开机自启那一路仍按上次的模式自动接管） */
function migrateOldConfig() {
  const cfg = lastStatus?.config;
  if (!cfg || cfg.autoSysproxy !== true) return;
  cfg.autoSysproxy = false;
  api('/config', { autoSysproxy: false }).catch(() => {});
}

function closeGuide() {
  markGuideSeen();
  closeModal($('guide'));
}

function closeCaPrompt() {
  markCaPromptSeen();
  closeModal($('ca-prompt'));
  runAfterCert();
}

/** 后端在「本机没存账号密码」时报的那句话：这不是登录失败，是还没开始配置 */
function noCredsError(msg) {
  return String(msg || '').includes('没有可用的账号密码');
}

/** 点「开启系统代理」但没登录时的提示（只在用户主动点按钮时出现，不再自动弹） */
function promptLogin() {
  if (lastStatus?.session?.loggedIn) return;
  const err = lastStatus?.session?.lastError;
  // 已经有明确的失败原因时弹的是「登录失败」那个窗口，不再来一个笼统的「还没登录」
  if (err && !noCredsError(err)) return;
  openModal($('login-prompt'));
}

/** 登录失败：弹窗 + 卡片里的红色横幅一起上，原因照原样显示（服务端给的就是中文）
    fromSave=true 表示这次填的是「保存并登录」里的新密码，false 表示用的是本机保存的账号 */
function showLoginFail(msg, fromSave = false) {
  loginFailShown = msg;
  $('login-fail-msg').textContent = msg;
  $('login-fail-note').textContent = fromSave
    ? '这次填的凭据没有被保存；本机原来那份能用的凭据保持不动。改好之后回到「账号与证书」再点一次「保存并登录」。'
    : '用的是本机保存的账号密码。如果密码已经改过，请到「账号与证书」填新密码再点「保存并登录」。';
  $('login-error-banner-msg').textContent = msg;
  $('login-error-banner').hidden = false;
  openModal($('login-fail'));
}

function showLoginFailOnce(msg) {
  // 已经有别的弹窗开着就先不抢，等下一轮轮询（横幅此刻已经显示了）
  if (msg === loginFailShown || anyModalOpen()) return;
  showLoginFail(msg);
}

/** 启动失败（不是账号/登录问题时）：端口被占、系统代理改不动等等 */
function showStartFail(msg) {
  $('start-fail-msg').textContent = msg || '未知原因';
  openModal($('start-fail'));
}

function goToAccount(focus = 'in-user') {
  for (const id of ['login-prompt', 'login-fail']) closeModal($(id));
  const card = $('card-account');
  card.scrollIntoView({ block: 'center', behavior: 'smooth' });
  card.classList.remove('flash');
  void card.offsetWidth; // 重启动画
  card.classList.add('flash');
  $(focus).focus();
}

async function installCaFromPrompt() {
  const btn = $('ca-prompt-install');
  $('ca-prompt-err').hidden = true;
  btn.disabled = true;
  btn.textContent = '安装中…';
  try {
    await api('/ca/install', {});
    $('ca-prompt-no-again').checked = true; // 装好了，以后不必再提示
    markCaPromptSeen();
    closeModal($('ca-prompt'));
    runAfterCert();
  } catch (e) {
    $('ca-prompt-err').textContent = `安装失败：${e.message}`;
    $('ca-prompt-err').hidden = false;
    appendLog({ t: new Date().toISOString(), msg: `安装根证书失败：${e.message}` });
  } finally {
    btn.disabled = false;
    btn.textContent = '立即安装';
    await refresh();
  }
}

$('btn-help').addEventListener('click', () => openModal($('guide')));
$('guide-ok').addEventListener('click', closeGuide);
$('guide-x').addEventListener('click', closeGuide);
$('login-prompt-go').addEventListener('click', () => goToAccount('in-user'));
$('login-prompt-later').addEventListener('click', () => closeModal($('login-prompt')));
$('login-prompt-x').addEventListener('click', () => closeModal($('login-prompt')));
$('ca-prompt-install').addEventListener('click', installCaFromPrompt);
$('ca-prompt-later').addEventListener('click', closeCaPrompt);
$('ca-prompt-x').addEventListener('click', closeCaPrompt);
$('login-fail-go').addEventListener('click', () => goToAccount('in-pass'));
$('login-fail-later').addEventListener('click', () => closeModal($('login-fail')));
$('login-fail-x').addEventListener('click', () => closeModal($('login-fail')));

/** 程序文件时间（unix 秒）→ 本地时间文本 */
function fmtStamp(secs) {
  const n = Number(secs || 0);
  if (!n) return '读不到';
  const d = new Date(n * 1000);
  const p = (v) => String(v).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 关于：版本 / 程序文件时间 / 控制接口 / 数据目录 */
function openAbout() {
  const cfg = lastStatus?.config || {};
  $('about-version').textContent = cfg.version ? 'v' + cfg.version : '—（核心没响应，暂时读不到）';
  $('about-built').textContent = fmtStamp(cfg.builtAt);
  $('about-port').textContent = String(cfg.controlPort || 8897);
  $('about-root').textContent = cfg.dataRoot || '—';
  openModal($('about'));
}

$('btn-about').addEventListener('click', openAbout);
$('about-ok').addEventListener('click', () => closeModal($('about')));
$('about-x').addEventListener('click', () => closeModal($('about')));
$('about-changelog').addEventListener('click', () => {
  closeModal($('about'));
  openModal($('changelog'));
});
$('changelog-ok').addEventListener('click', () => closeModal($('changelog')));
$('changelog-x').addEventListener('click', () => closeModal($('changelog')));

/* ---------- 二级弹窗：校内导航 / 在线分流规则 ---------- */
function openPortal() {
  drawPortal();
  openModal($('portal'));
  setTimeout(() => $('in-portal-search').focus(), 60);
}
$('btn-portal').addEventListener('click', () => guard(openPortal));
$('portal-ok').addEventListener('click', () => closeModal($('portal')));
$('portal-x').addEventListener('click', () => closeModal($('portal')));

function openOnlineRules() {
  const o = lastStatus?.online || {};
  $('in-online-url').value = (Array.isArray(o.urls) ? o.urls : []).join('\n');
  openModal($('online-modal'));
  setTimeout(() => $('in-online-url').focus(), 60);
}
$('btn-online-open').addEventListener('click', openOnlineRules);
$('online-ok').addEventListener('click', () => closeModal($('online-modal')));
$('online-x').addEventListener('click', () => closeModal($('online-modal')));

// 「分流规则」的红色感叹号：鼠标悬浮/键盘聚焦本来就会显示说明，点一下可以把它钉住
// （再点、点别处、ESC 都会收起来），触屏或不想按住鼠标的人也能读完。
const rulesTip = $('rules-tip').closest('.tip-wrap');
$('rules-tip').addEventListener('click', (e) => {
  e.stopPropagation();
  rulesTip.classList.toggle('open');
});
document.addEventListener('click', (e) => {
  if (!rulesTip.contains(e.target)) rulesTip.classList.remove('open');
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  rulesTip.classList.remove('open');
  // A4：ESC 与「✕」走同一套收尾（该写标记的写标记、该继续首启链的继续），
  // 不能只是把窗口藏起来。
  const closers = {
    'online-modal': () => closeModal($('online-modal')),
    portal: () => closeModal($('portal')),
    changelog: () => closeModal($('changelog')),
    about: () => closeModal($('about')),
    doctor: () => closeModal($('doctor')),
    'proxy-conflict': closeConflict,
    'forget-confirm': () => closeModal($('forget-confirm')),
    'start-fail': () => closeModal($('start-fail')),
    'login-fail': () => closeModal($('login-fail')),
    'ca-prompt': closeCaPrompt,
    'login-prompt': () => closeModal($('login-prompt')),
    guide: closeGuide,
  };
  for (const id of ['online-modal', 'portal', 'changelog', 'about', 'doctor', 'proxy-conflict', 'forget-confirm', 'start-fail', 'login-fail', 'ca-prompt', 'login-prompt', 'guide']) {
    if (!$(id).hidden) {
      closers[id]();
      break;
    }
  }
});
$('start-fail-ok').addEventListener('click', () => closeModal($('start-fail')));
$('start-fail-x').addEventListener('click', () => closeModal($('start-fail')));

/* ---------- 通用包装 ---------- */
async function guard(fn) {
  try {
    await fn();
  } catch (e) {
    appendLog({ t: new Date().toISOString(), msg: `操作失败：${e.message}` });
  } finally {
    await refresh();
    await pollLogs();
  }
}

/* ---------- 启动 ---------- */
async function boot() {
  applyTheme(themePref());
  await initAutostart();
  await refresh();

  // 核心随程序无感启动（界面里没有「启动核心」按钮了）：没账号/没登录时它会待命，
  // 等登录成功后再由下面的轮询自动拉起来；起不来只在顶部横幅里说一声。
  maybeShowFirstRun();
  migrateOldConfig();
  // 本机存了账号才主动拉核心：没账号时它会立刻失败，只会在日志里留一行没必要的报错
  // （登进去之后由下面的轮询自动拉起来）
  if (lastStatus?.session?.hasCreds) ensureCore();

  setInterval(() => {
    refresh().then(() => {
      // 登录成功那一刻（或会话恢复）自动把核心拉起来
      if (!starting && !coreError && lastStatus?.session?.loggedIn && !lastStatus?.proxy?.running) {
        ensureCore();
      }
    });
    pollLogs();
  }, 2000);
  await pollLogs();
}

boot();
