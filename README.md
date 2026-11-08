# SDUST WebVPN 本地透明代理

**在校外，用校内原始地址直接访问学校资源。**

浏览器、`git`、`pip`、`npm`、`conda`、`curl`、Python/Node 脚本全部照常使用 ——
不用先打开 WebVPN 门户，不用手动点开改写后的链接，登录态自动续期，系统代理一键接管。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6)
![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB)

> 本仓库只包含桌面端本体（界面 + Rust 内核）。开发期的调试脚本、早期 Node 实现、
> 构建产物与运行时数据都不在版本库里。

---

## 它解决什么问题

学校用的是**网瑞达 WebVPN**（clientless 反向代理）：所有资源都被改写成
`https://webvpn.sdust.edu.cn/https/<hex>/<path>` 这种形式，只能在门户里点着用。
于是校外的日常开发会很别扭：

| 没有本项目 | 有了本项目 |
| --- | --- |
| 打开门户 → 找到入口 → 点进去 | 直接访问 `https://my.sdust.edu.cn` |
| `git clone` 得手动复制改写后的地址 | `git clone https://gitlab.sdust.edu.cn/...` 照常 |
| `pip install` 校内源要改 index-url | 不用改任何配置 |
| 页内链接、302 跳转全是 webvpn 前缀 | 链接、`Location`、Cookie 全部还原成原始地址 |
| 登录态过期要重新输入 | 自动保活，过期自动重登 |

原理很短：本机跑一个 HTTP(S) 代理 → 白名单命中的请求自动改写成 WebVPN 的
`/http/<hex>/<path>` 形式并转发 → 响应里的链接、`Location`、`Set-Cookie` 再还原回原始地址；
站外流量直连，不影响速度。HTTPS 用本地 CA 做中间人解密，否则无法改写页面里的链接。

## 特性

- **透明代理** —— 白名单命中走 WebVPN，其余直连；`PAC` / 全局两种模式
- **完整协议改写** —— HTML 链接、CSS/JS 里的绝对地址、`Location`、`Set-Cookie`、
  CSP 头，以及门户注入函数（`vpn_eval` / `vpn_get_obj` / `vpn_set_obj` / `vpn_call_fn`）
  的兼容层
- **HTTPS 中间人** —— 本地 CA（ECDSA P-256）+ 按站点签发证书，一键安装/卸载到
  Windows 证书库（装完回读校验），私钥只留在本机
- **会话自动保活** —— 5 分钟一次心跳，票据过期自动重新登录；连续失败会退避，
  避免把 CAS 刷出验证码
- **系统代理接管** —— PAC（默认）/ 全局，接管前自动备份原设置，退出时还原；
  能区分「被本程序接管 / 被别的软件（如 Clash）占用 / 上次异常退出的残留」
- **在线分流规则** —— 支持从远端拉取规则（JSON / Clash `payload` / 纯文本分段），
  默认 24 小时同步一次，断网时回落到本机缓存的那份
- **纯本地、便携** —— 数据目录跟着 exe 走，换目录就是一份全新配置；
  不要求管理员权限（证书装到当前用户，系统代理写 `HKCU`）
- **状态检查** —— 一键体检：控制接口 / 会话 / 核心 / 系统代理归属 / 根证书 / 学校直连

## 能力边界

| ✅ 能用（HTTP/HTTPS） | ❌ 用不了（原生 TCP） |
| --- | --- |
| 浏览器访问 `http(s)://xxx.sdust.edu.cn`、校内 IP 站点 | SSH / SFTP |
| `git clone https://...`（学校 GitLab 等） | MySQL / PostgreSQL / Redis |
| `pip` / `npm` / `conda` / `maven` 校内源 | RDP / VNC |
| `curl` / `wget` / 下载器（HTTP） | FTP / BT / 其它私有 TCP 协议 |
| Python `requests`、Node `fetch` 等 | VS Code Remote-SSH、JetBrains Gateway |

原因：WebVPN 是 **clientless 反向代理**，所有协议都封装在 443 的 HTTP 里，没有 TCP 隧道。
SSH/MySQL/RDP 这些只能走学校提供的网页终端/网页工具。

## 运行时要

- Windows 10 / 11 x64
- **WebView2 运行时**：Win11 自带；Win10 通常随 Edge 已装，缺了装一次
  [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
- **不需要 Node.js**，**不需要管理员权限**

## 使用

1. 双击 `SDUST WebVPN.exe`。首次打开弹一次「首次使用 · 两步开始」引导；
   核心（本地代理 `127.0.0.1:8899`）随程序自动启动，但**不会**自动改系统代理
2. 「账号与证书」里填账号（职工号 / 学号 / 邮箱 / 别名）和密码 → 「保存并登录」
3. 第一次点「开启系统代理」会先提示装一次根证书；装完即可接管（默认 PAC 模式）
4. 之后浏览器、git、pip 直接访问校内原始地址即可
5. 关窗口是**隐藏到托盘**（核心继续跑）；托盘右键可开/关系统代理或退出。
   「关闭系统代理」或退出程序都会还原系统代理设置

**分流规则**：由白名单（命中走 WebVPN）和黑名单（命中直连，优先级更高）决定，都没命中就直连。

- 条目支持 `sdust.edu.cn`（含子域）、`*.example.com`、`10.0.0.0/8`、`192.168.1.5`、`*`
- 名单只在 **PAC 模式**生效；全局模式除 `webvpn.sdust.edu.cn` /
  `localhost` / `127.0.0.0/8` 外全部经 WebVPN 出去
- 保存后立即生效：PAC 模式会换 `AutoConfigURL` 的版本号触发客户端重新拉取脚本，
  无需重启浏览器

## 架构

```
SDUST WebVPN.exe (Tauri 2)
├─ 界面 (WebView2)        ui/  index.html + style.css + main.js + sites.js
│     └─ fetch → http://127.0.0.1:8897   (控制 API，只监听回环)
└─ 进程内 tokio 内核      src-tauri/src/vpn/
      core.rs      控制 API（axum）+ 生命周期 + 日志
      session.rs   CAS 登录、保活、Cookie 会话
      proxy.rs     HTTP/HTTPS 代理、CONNECT + MITM、转发
      rewrite.rs   链接 / Location / Set-Cookie 还原
      wrd.rs       WebVPN 地址编码、密码加密（AES-128-CFB）
      rules.rs     白名单 / 黑名单匹配
      online.rs    在线分流规则解析与同步
      certs.rs     本地 CA 与站点证书（rcgen + rustls）
      certstore.rs Windows 根证书库读写（Crypt32）
      sysproxy.rs  系统代理 / PAC / 环境变量（注册表）
      dpapi.rs     凭据加密（CryptProtectData）
      creds.rs / cookies.rs / pac.rs / paths.rs
```

端口：控制 API `127.0.0.1:8897`，本地代理 `127.0.0.1:8899`，均只监听回环。

## 目录结构

```
.
├── package.json              前端构建脚本（@tauri-apps/cli）
├── pnpm-lock.yaml
├── ui/                       界面（纯静态，无需打包器）
│   ├── index.html
│   ├── style.css
│   ├── main.js
│   └── sites.js              校内导航内置清单
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── build.rs
    ├── capabilities/
    ├── icons/
    └── src/
        ├── main.rs           窗口、托盘、单实例、开机自启、数据目录解析
        └── vpn/              代理内核（见上方架构）
```

## 构建

前置：Rust ≥ 1.77、Node.js、pnpm、MSVC 工具链。

```powershell
pnpm install
pnpm tauri build          # 产物：src-tauri/target/release/sdust-webvpn.exe
```

调试：

```powershell
pnpm tauri dev            # 界面 + 内核一起跑
```

```powershell
cd src-tauri
cargo test                # 单测：wrd 编解码、rewrite、pac、sysproxy、certs、dpapi、proxy
cargo run -- --core-only  # 无界面只跑内核，便于调控制 API
```

> **开发时的数据目录**：exe 默认把「自己所在的目录」当数据目录，所以直接 `cargo run`
> 会在 `target/debug|release` 里另建一份 `state\`。把
> [`src-tauri/.cargo/config.toml.example`](src-tauri/.cargo/config.toml.example)
> 复制成同目录下的 `config.toml`，就会用 `[env] VPN_HOME` 把它钉回工程根
> （该文件已被 `.gitignore` 排除，因为它是本机私有的）。
>
> **只改 `ui/` 下的前端文件时 cargo 不会重编**，exe 里仍是旧资源，
> 构建前先 `(Get-Item src/main.rs).LastWriteTime = Get-Date` 强制重编。

## 数据目录与隐私

数据目录 = **exe 自己所在的目录**，`state\` 与 `.secrets\` 都建在旁边：

- 把 exe 拷到任意文件夹，第一次运行会在旁边自动生成 `state\`、`.secrets\`
- 换文件夹 = 一份全新、互不干扰的配置
- 想共用同一份配置：把 exe 放进已经有 `state\` 的那个文件夹
- 环境变量 `VPN_HOME` 优先级最高（主要给开发调试用）
- 界面「说明」卡片底部显示当前实际生效的路径

**关于隐私**：账号密码用 Windows DPAPI 加密后存在 `.secrets\creds.dpapi`（只有同一 Windows
用户能解密）；本地 CA 私钥在 `state\ca\`；Cookie 在 `state\cookies.json`。这些都在你自己的
机器上，不会被上传 —— 本程序没有自建后端，只和学校 WebVPN 通信。仓库里也不包含任何
账号、Cookie、证书或运行日志。

## 控制接口

界面与内核之间是本机 HTTP（`http://127.0.0.1:8897`，只监听回环）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/status` | 全量状态：会话、代理、系统代理归属、分流规则、在线规则、版本 |
| GET | `/logs` | 内存里最近 800 行日志 |
| GET | `/pac` | 生成 PAC 脚本 |
| POST | `/login` `/logout` `/credentials` | 登录 / 登出 / 保存凭据 |
| POST | `/proxy/start` `/proxy/stop` | 启动 / 停止代理 |
| POST | `/sysproxy` `/envproxy` | 接管 / 还原系统代理与环境变量 |
| POST | `/config` `/online` | 改配置 / 同步在线规则 |
| POST | `/ca/install` `/ca/uninstall` | 安装 / 卸载根证书 |
| POST | `/doctor` | 体检，返回逐项结果与修法 |
| POST | `/quit` | 退出（会先还原系统代理） |

## 已知限制

- 仅 Windows；仅 HTTP/HTTPS（见上方「能力边界」）
- 与其它**同样依赖系统代理**的软件（Clash、v2rayN 等）互斥。本程序只占用系统代理这一个
  开关：请把翻墙软件切到 TUN / 虚拟网卡模式，并把 `*.sdust.edu.cn` 与学校地址段设为直连
- 需要信任本机 CA 才能解密 HTTPS；介意的话可以只用 HTTP 资源

## 免责声明

仅供本校师生在校外访问学校已授权的资源使用。请遵守学校网络使用规定与相关法律法规，
不要用于任何未授权的访问。使用本软件产生的后果由使用者自行承担。

## 许可证

[MIT](LICENSE)
