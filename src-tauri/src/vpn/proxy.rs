//! 本地 HTTP/HTTPS 透明代理（hyper + rustls，进程内运行）。
//!
//! 校内地址 → 转成 `https://webvpn.sdust.edu.cn/{http|https}/{hex}/path`；
//! https 目标做 TLS 中间人（本地 CA 即时签发），响应里的链接/跳转/Cookie 改写回原始地址；
//! 非校内地址直连或 TCP 隧道。

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::certs::Ca;
use super::rewrite::{
    inject_vpn_shim, rewrite_links, rewrite_set_cookie, rewrite_url, strip_vpn_scripts,
};
use super::rules::{Decision, RuleSet};
use super::session::Session;
use super::wrd::{encode_host, WEBVPN_ORIGIN};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxErr>;

pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;

const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_TEXT: usize = 32 * 1024 * 1024;

static TEXT_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:text/|application/(?:json|javascript|ecmascript|xml|xhtml\+xml|ld\+json|rss\+xml)|image/svg\+xml)")
        .unwrap()
});

#[derive(Default)]
pub struct Stats {
    pub school: AtomicU64,
    pub direct: AtomicU64,
    pub rewrites: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "school": self.school.load(Ordering::Relaxed),
            "direct": self.direct.load(Ordering::Relaxed),
            "rewrites": self.rewrites.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
        })
    }
}

/// 规则句柄：改配置时整体替换内部 Arc，已在跑的连接不受影响
pub type RulesHandle = Arc<parking_lot::RwLock<Arc<RuleSet>>>;

fn decide(ctx: &Ctx, host: &str) -> Decision {
    ctx.rules.read().decide(host)
}

#[derive(Clone)]
struct Ctx {
    session: Arc<Session>,
    ca: Arc<Ca>,
    rules: RulesHandle,
    stats: Arc<Stats>,
    log: LogFn,
}

pub struct Proxy {
    pub port: u16,
    pub stats: Arc<Stats>,
    stop: tokio::sync::oneshot::Sender<()>,
}

impl Proxy {
    pub fn stop(self) {
        let _ = self.stop.send(());
    }
}

pub async fn start(
    ca: Arc<Ca>,
    session: Arc<Session>,
    port: u16,
    rules: RulesHandle,
    log: LogFn,
) -> Result<Proxy, String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("监听 127.0.0.1:{port} 失败：{e}"))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let stats = Arc::new(Stats::default());
    let ctx = Ctx {
        session,
        ca,
        rules,
        stats: stats.clone(),
        log: log.clone(),
    };
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req| handle_plain(req, ctx.clone()));
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, svc)
                            .with_upgrades()
                            .await
                        {
                            let msg = e.to_string();
                            if !msg.contains("closed") && !msg.contains("reset") {
                                tracing_log(&msg);
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(Proxy { port, stats, stop: tx })
}

fn tracing_log(msg: &str) {
    eprintln!("[proxy] {msg}");
}

pub fn fail(code: u16, msg: &str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from(format!("[sdust-webvpn-local] {msg}\n")))
        .map_err(|e: Infallible| match e {})
        .boxed();
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY))
        .header("content-type", "text/plain; charset=utf-8")
        .body(body)
        .unwrap()
}

fn empty_ok() -> Response<BoxBody> {
    Response::new(Full::new(Bytes::new()).map_err(|e: Infallible| match e {}).boxed())
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
    )
}

fn host_of(uri: &hyper::Uri) -> (String, u16) {
    let host = uri.host().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
    let port = uri.port_u16().unwrap_or(80);
    (host, port)
}

async fn handle_plain(req: Request<hyper::body::Incoming>, ctx: Ctx) -> Result<Response<BoxBody>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, ctx).await);
    }
    let uri = req.uri().clone();
    let (host, port, path) = if uri.scheme().is_some() {
        let host = uri.host().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
        let path = format!("{}{}", uri.path(), uri.query().map(|q| format!("?{q}")).unwrap_or_default());
        (host, port, path)
    } else {
        let host_header = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let (h, p) = split_host_port(&host_header, 80);
        let path = uri.to_string();
        (h, p, path)
    };

    if host.is_empty() {
        return Ok(fail(400, "缺少 Host"));
    }
    if decide(&ctx, &host) == Decision::Direct {
        ctx.stats.direct.fetch_add(1, Ordering::Relaxed);
        if uri.scheme_str() == Some("https") {
            return Ok(fail(400, "https 请使用 CONNECT"));
        }
        return Ok(direct(req, &format!("http://{host}:{port}{path}"), &ctx).await);
    }
    Ok(proxy_school(req, "http", &host, port, &path, &ctx).await)
}

async fn handle_connect(req: Request<hyper::body::Incoming>, ctx: Ctx) -> Response<BoxBody> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let (host, port) = split_host_port(&authority, 443);
    if host.is_empty() {
        return fail(400, "CONNECT 目标不合法");
    }

    if decide(&ctx, &host) == Decision::Direct {
        ctx.stats.direct.fetch_add(1, Ordering::Relaxed);
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    match TcpStream::connect((host.as_str(), port)).await {
                        Ok(mut tcp) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut tcp).await;
                        }
                        Err(e) => (ctx2.log)(format!("直连 {host}:{port} 失败：{e}")),
                    }
                }
                Err(e) => (ctx2.log)(format!("CONNECT 升级失败：{e}")),
            }
        });
        return empty_ok();
    }

    let cfg = match ctx.ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            (ctx.log)(format!("签发 {host} 证书失败：{e}"));
            return fail(502, &e);
        }
    };
    let ctx2 = ctx.clone();
    let host2 = host.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let acceptor = TlsAcceptor::from(cfg);
                match acceptor.accept(TokioIo::new(upgraded)).await {
                    Ok(tls) => {
                        let svc = {
                            let ctx = ctx2.clone();
                            let host = host2.clone();
                            service_fn(move |req| {
                                handle_mitm(req, ctx.clone(), host.clone(), port)
                            })
                        };
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), svc)
                            .with_upgrades()
                            .await;
                    }
                    Err(e) => (ctx2.log)(format!("TLS 握手失败（{host2}）：{e}")),
                }
            }
            Err(e) => (ctx2.log)(format!("CONNECT 升级失败：{e}")),
        }
    });
    empty_ok()
}

async fn handle_mitm(
    req: Request<hyper::body::Incoming>,
    ctx: Ctx,
    host: String,
    port: u16,
) -> Result<Response<BoxBody>, Infallible> {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(proxy_school(req, "https", &host, port, &path, &ctx).await)
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (s.to_string(), default_port),
    }
}

/// 把浏览器的请求头透传给上游（去掉逐跳头和我们会覆盖的那几个）。
/// 少了 `content-type` 这类头，很多站点的 POST 会被当成空请求处理。
fn forward_request_headers(
    headers: &hyper::HeaderMap,
    mut rb: reqwest::RequestBuilder,
    cookie: Option<String>,
) -> reqwest::RequestBuilder {
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("cookie")
            || name.eq_ignore_ascii_case("accept-encoding")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            // 不转发条件请求头：上游一旦回 304，XHR 拿到空 body，
            // jQuery 的 JSON.parse('') 会报 "Unexpected end of JSON input"
            || name.eq_ignore_ascii_case("if-none-match")
            || name.eq_ignore_ascii_case("if-modified-since")
            || name.eq_ignore_ascii_case("if-range")
        {
            continue;
        }
        if let Ok(s) = v.to_str() {
            rb = rb.header(name, s);
        }
    }
    if let Some(c) = cookie {
        if !c.is_empty() {
            rb = rb.header("cookie", c);
        }
    }
    rb
}

/// 浏览器带来的 Cookie（站点自己的会话）
fn client_cookie(headers: &hyper::HeaderMap) -> String {
    headers
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}
async fn proxy_school(
    req: Request<hyper::body::Incoming>,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    ctx: &Ctx,
) -> Response<BoxBody> {
    ctx.stats.school.fetch_add(1, Ordering::Relaxed);
    let method = req.method().clone();
    let client_headers = req.headers().clone();

    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
            return fail(413, &format!("读取请求体失败：{e}"));
        }
    };
    if body.len() > MAX_BODY {
        ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
        return fail(413, "请求体过大");
    }

    let default_port = if scheme == "https" { 443 } else { 80 };
    let key = if port == 0 || port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let upstream = format!(
        "{WEBVPN_ORIGIN}/{scheme}/{}{}",
        encode_host(&key),
        if path.starts_with('/') { path.to_string() } else { format!("/{path}") }
    );

    for attempt in 0..2 {
        let mut rb = ctx
            .session
            .client
            .request(method.clone(), &upstream)
            .header("accept-encoding", "identity")
            .header("x-forwarded-host", host);
        let mut merged = client_cookie(&client_headers);
        let vpn = ctx.session.cookie_header();
        if !vpn.is_empty() {
            if !merged.is_empty() {
                merged.push_str("; ");
            }
            merged.push_str(&vpn);
        }
        rb = forward_request_headers(&client_headers, rb, Some(merged));
        if !body.is_empty() || method == Method::POST || method == Method::PUT {
            rb = rb.body(body.clone());
        }
        let res = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                return fail(502, &format!("WebVPN 请求失败：{e}"));
            }
        };

        if (300..400).contains(&res.status().as_u16()) && attempt == 0 {
            let loc = res
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if loc.contains("/login") {
                (ctx.log)("票据失效，正在重新登录…".into());
                if let Err(e) = ctx.session.login().await {
                    ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
                    return fail(502, &format!("重新登录失败：{e}"));
                }
                continue;
            }
        }
        return relay(res, method == Method::HEAD, ctx).await;
    }
    fail(502, "WebVPN 请求失败")
}

/// 有的老系统把 JSON 用 `text/html` 发回来（例如 `.shtml` 接口），
/// 这种内容不能当 HTML 改写/注入，否则 `JSON.parse` 直接炸。
fn looks_like_html(content_type: &str, body: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if !(ct.contains("text/html") || ct.contains("application/xhtml")) {
        return false;
    }
    let t = body.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        return false;
    }
    let head: String = t.chars().take(400).collect::<String>().to_ascii_lowercase();
    head.starts_with("<!doctype") || head.starts_with("<html") || head.contains("<html")
        || head.contains("<head")
        || head.contains("<body")
}
async fn relay(res: reqwest::Response, head_only: bool, ctx: &Ctx) -> Response<BoxBody> {
    let status = res.status();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_text = TEXT_TYPE.is_match(&content_type);

    let mut builder = Response::builder().status(status.as_u16());
    for (k, v) in res.headers().iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("content-encoding") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if name.eq_ignore_ascii_case("location") {
            let loc = v.to_str().unwrap_or("");
            builder = builder.header("location", rewrite_url(loc));
            continue;
        }
        if name.eq_ignore_ascii_case("set-cookie") {
            let line = v.to_str().unwrap_or("");
            builder = builder.header("set-cookie", rewrite_set_cookie(line));
            continue;
        }
        // HTML 会被注入 vpn_* 兼容层，不能让浏览器拿 304 复用旧副本
        if content_type.to_ascii_lowercase().contains("html")
            && (name.eq_ignore_ascii_case("etag") || name.eq_ignore_ascii_case("last-modified"))
        {
            continue;
        }
        builder = builder.header(k.clone(), v.clone());
    }

    if !is_text {
        let stream = res.bytes_stream().map_ok(Frame::data).map_err(|e| -> BoxErr { Box::new(e) });
        let body = http_body_util::BodyExt::boxed(StreamBody::new(stream));
        return builder.body(body).unwrap_or_else(|_| fail(502, "响应头不合法"));
    }

    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(e) => {
            ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
            return fail(502, &format!("读取响应失败：{e}"));
        }
    };
    if bytes.len() > MAX_TEXT {
        ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
        return fail(502, "响应过大，无法改写");
    }
    let text = String::from_utf8_lossy(&bytes).to_string();
    let is_html = looks_like_html(&content_type, &text);
    let mut out = rewrite_links(&text);
    if is_html {
        out = strip_vpn_scripts(&out);
        out = inject_vpn_shim(&out);
    }
    if out != text {
        ctx.stats.rewrites.fetch_add(1, Ordering::Relaxed);
    }
    let len = out.len();
    let body = if head_only {
        Bytes::new()
    } else {
        Bytes::from(out)
    };
    builder
        .header("content-length", len.to_string())
        .body(http_body_util::BodyExt::boxed(Full::new(body).map_err(|e: Infallible| match e {})))
        .unwrap_or_else(|_| fail(502, "响应头不合法"))
}

async fn direct(
    req: Request<hyper::body::Incoming>,
    url: &str,
    ctx: &Ctx,
) -> Response<BoxBody> {
    let method = req.method().clone();
    let client_headers = req.headers().clone();
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return fail(413, &format!("读取请求体失败：{e}")),
    };
    let mut rb = ctx.session.client.request(method, url).header("accept-encoding", "identity");
    let ck = client_cookie(&client_headers);
    rb = forward_request_headers(&client_headers, rb, Some(ck));
    if !body.is_empty() {
        rb = rb.body(body);
    }
    match rb.send().await {
        Ok(res) => {
            let status = res.status();
            let mut builder = Response::builder().status(status.as_u16());
            for (k, v) in res.headers().iter() {
                let name = k.as_str();
                if is_hop_by_hop(name) || name.eq_ignore_ascii_case("content-encoding") {
                    continue;
                }
                builder = builder.header(k.clone(), v.clone());
            }
            let stream = res.bytes_stream().map_ok(Frame::data).map_err(|e| -> BoxErr { Box::new(e) });
            builder
                .body(http_body_util::BodyExt::boxed(StreamBody::new(stream)))
                .unwrap_or_else(|_| fail(502, "响应头不合法"))
        }
        Err(e) => {
            ctx.stats.errors.fetch_add(1, Ordering::Relaxed);
            fail(502, &format!("直连失败：{e}"))
        }
    }
}

#[allow(dead_code)]
fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_authorities() {
        assert_eq!(split_host_port("a.b:8080", 443), ("a.b".to_string(), 8080));
        assert_eq!(split_host_port("a.b", 443), ("a.b".to_string(), 443));
        assert_eq!(split_host_port("[::1]:9000", 443), ("::1".to_string(), 9000));
    }

    #[test]
    fn html_sniff_handles_multibyte() {
        // 第 400 字节正好落在中文里：以前按字节切片会 panic 并把整个程序 abort
        let mut html = String::from("<!DOCTYPE html><html><head><title>");
        while html.len() < 380 {
            html.push('科');
        }
        html.push_str("</title></head><body>网易</body></html>");
        assert!(looks_like_html("text/html; charset=utf-8", &html));
        assert!(!looks_like_html("text/html", "{\"ok\":true}"));
        assert!(!looks_like_html("application/json", "<html></html>"));
    }
}
