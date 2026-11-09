#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State, WindowEvent};

mod vpn;

use vpn::core::Core;

struct AppState {
    core: Arc<Core>,
}

/// 只有托盘菜单「退出」才真的退出；点窗口 X 只是隐藏
static QUITTING: AtomicBool = AtomicBool::new(false);

/// 数据目录：VPN_HOME > 可执行文件所在目录（便携）。
///
/// exe 放哪，`state\` 与 `.secrets\` 就建在哪；换个文件夹就是一份互不干扰的
/// 全新配置，绝不会回落到编译机器上的项目目录。
/// 开发运行（cargo run / tauri dev）由 `desktop/src-tauri/.cargo/config.toml`
/// 里的 `[env] VPN_HOME` 指回项目根，见 README「开发与构建」。
fn data_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VPN_HOME") {
        let p = p.trim();
        if !p.is_empty() {
            return Some(clean(PathBuf::from(p)));
        }
    }

    let exe = std::env::current_exe().ok()?;
    Some(exe.parent()?.to_path_buf())
}

/// 把路径里的 `.` / `..` 去掉（`.cargo/config.toml` 里的 VPN_HOME 是相对路径写法，
/// 归一化后界面「数据目录」才显示得干净）；路径还不存在时原样返回。
fn clean(p: PathBuf) -> PathBuf {
    match std::fs::canonicalize(&p) {
        Ok(abs) => {
            // Windows 归一化后会带长路径前缀：\\?\E:\Projects\VPN
            let s = abs.to_string_lossy();
            match s.strip_prefix(r"\\?\") {
                Some(rest) => PathBuf::from(rest),
                None => abs,
            }
        }
        Err(_) => p,
    }
}

fn launched_by_autostart() -> bool {
    std::env::args().any(|a| a == "--autostart")
}

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_NAME: &str = "SDUST WebVPN";

fn run_reg(args: &[&str]) -> bool {
    use std::process::{Command, Stdio};
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new("reg");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.status() {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

#[tauri::command]
fn autostart_get() -> bool {
    run_reg(&["query", RUN_KEY, "/v", RUN_NAME])
}

#[tauri::command]
fn autostart_set(enabled: bool) -> Result<bool, String> {
    let ok = if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let value = format!("\"{}\" --autostart", exe.display());
        run_reg(&["add", RUN_KEY, "/v", RUN_NAME, "/t", "REG_SZ", "/d", &value, "/f"])
    } else {
        // 键值本来不存在时 reg 返回 1，视为成功
        run_reg(&["delete", RUN_KEY, "/v", RUN_NAME, "/f"]) || !autostart_get()
    };
    if ok {
        Ok(enabled)
    } else {
        Err("写注册表 Run 键失败".into())
    }
}

/// 启动内核；开机自启这一条路会顺手按上次的模式接管系统代理。
/// 界面上的「开启系统代理」和托盘菜单负责普通启动时的接管。
async fn start_core_impl(core: &Arc<Core>) -> Result<serde_json::Value, String> {
    // 幂等：已启动就只返回当前状态（程序启动与界面自动启动可能同时触发）
    if core.proxy_running() {
        let port = core.proxy_port();
        return Ok(serde_json::json!({ "running": true, "port": port }));
    }
    // 还没保存账号（全新安装，或刚点过「清除本机账号」）不算故障：核心待命就行。
    // 在界面上填好账号密码并登录成功后，前端的轮询会自动把它拉起来。
    if !core.session.has_creds() && !core.session.logged_in() {
        core.log("还没有保存账号：核心待命（填好账号密码并登录后自动启动）");
        return Ok(serde_json::json!({ "running": false, "idle": true }));
    }
    let (running, port) = core.start_proxy(None).await?;

    // 核心现在随程序无感启动，普通启动**不碰系统代理**（要点「开启系统代理」才接管）；
    // 只有开机自启（--autostart，静默驻留托盘）按上次的模式自动接管。
    if launched_by_autostart() {
        let pac = core.cfg.lock().sysproxy_mode == "pac";
        match core.enable_sysproxy_saved() {
            Ok(_) => core.log(if pac {
                "已自动接管系统代理（PAC 模式）"
            } else {
                "已自动接管系统代理（全局模式）"
            }),
            Err(e) => core.log(format!("自动接管系统代理失败：{e}")),
        }
    }
    Ok(serde_json::json!({ "running": running, "port": port }))
}

#[tauri::command]
async fn core_start(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    start_core_impl(&state.core).await
}

#[tauri::command]
async fn core_stop(state: State<'_, AppState>) -> Result<bool, String> {
    state.core.stop_proxy();
    Ok(state.core.proxy_running())
}

#[tauri::command]
fn core_running(state: State<'_, AppState>) -> bool {
    state.core.proxy_running()
}

#[tauri::command]
fn project_info(state: State<'_, AppState>) -> serde_json::Value {
    serde_json::json!({
        "root": state.core.paths.root.display().to_string(),
        "found": true,
        "controlPort": vpn::core::CONTROL_PORT,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// 托盘菜单「退出」：真正退出，退出时 RunEvent::Exit 会还原系统代理
#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    QUITTING.store(true, Ordering::SeqCst);
    app.exit(0);
}

/// 用系统默认浏览器打开一个 http(s) 链接（校内导航用）。
/// 走 ShellExecuteW（Windows 自己的「打开方式」），不经过 cmd，所以不会闪黑框。
#[tauri::command]
fn open_external(url: String) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let u = url.trim();
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return Err("只支持 http/https 链接".into());
    }
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = u.encode_utf16().chain(std::iter::once(0)).collect();
    let h = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // 返回值小于等于 32 都是错误码（0 = 内存不足，2 = 找不到文件，5 = 拒绝访问…）
    if (h as isize) <= 32 {
        return Err(format!("系统没能打开这个链接（ShellExecuteW 返回 {}）", h as isize));
    }
    Ok(())
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "打开界面", true, None::<&str>)?;
    let sys_on = MenuItem::with_id(app, "sys_on", "开启系统代理", true, None::<&str>)?;
    let sys_off = MenuItem::with_id(app, "sys_off", "关闭系统代理", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &sys_on, &sys_off, &sep, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("SDUST WebVPN — 校内资源透明访问")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "sys_on" => {
                // 核心是随程序常驻的，这里只负责"接管系统代理"；
                // 没登录/没账号会在这里报错，把窗口叫出来让人看到原因。
                let core = app.state::<AppState>().core.clone();
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = start_core_impl(&core).await {
                        core.log(format!("从托盘接管失败（核心没起来）：{e}"));
                        show_main(&handle);
                        return;
                    }
                    // 核心没真正跑起来（比如还没保存账号）就别接管系统代理，
                    // 否则整机流量会被指到一个什么都做不了的代理上。
                    if !core.proxy_running() {
                        core.log("没法开启系统代理：核心还没有运行（先在界面里登录）");
                        show_main(&handle);
                        return;
                    }
                    match core.enable_sysproxy_saved() {
                        Ok(_) => core.log(if core.cfg.lock().sysproxy_mode == "pac" {
                            "已接管系统代理（PAC 模式）"
                        } else {
                            "已接管系统代理（全局模式）"
                        }),
                        Err(e) => {
                            core.log(format!("接管系统代理失败：{e}"));
                            show_main(&handle);
                        }
                    }
                });
            }
            "sys_off" => {
                // 只还原系统代理，核心继续跑（核心现在随程序走）
                let core = app.state::<AppState>().core.clone();
                match core.release_sysproxy() {
                    Ok(_) => core.log("系统代理已还原（核心继续运行）"),
                    Err(e) => core.log(format!("还原系统代理失败：{e}")),
                }
            }
            "quit" => {
                QUITTING.store(true, Ordering::SeqCst);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn main() {
    let root = match data_root() {
        Some(r) => r,
        None => {
            eprintln!("找不到数据目录（可设置环境变量 VPN_HOME）");
            std::process::exit(2);
        }
    };

    let core = match Core::new(root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("核心初始化失败：{e}");
            std::process::exit(3);
        }
    };

    // 无界面模式：只跑内核与控制接口（便于命令行调试/无 WebView2 环境）
    if std::env::args().any(|a| a == "--core-only") {
        let rt = tokio::runtime::Runtime::new().expect("创建 tokio 运行时失败");
        let c = core.clone();
        rt.block_on(async move {
            let serving = c.clone();
            tokio::spawn(async move {
                if let Err(e) = serving.serve_control().await {
                    c.log(format!("控制接口退出：{e}"));
                }
            });
            let _ = tokio::signal::ctrl_c().await;
        });
        core.shutdown();
        return;
    }

    let control = core.clone();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }))
        .manage(AppState { core: core.clone() })
        .invoke_handler(tauri::generate_handler![
            core_start,
            core_stop,
            core_running,
            project_info,
            autostart_get,
            autostart_set,
            quit_app,
            open_external
        ])
        .setup(move |app| {
            // 控制接口 POST /quit 也能干净退出（退出时走 RunEvent::Exit 的还原逻辑）
            let handle_for_quit = app.handle().clone();
            crate::vpn::core::set_quit_hook(move || {
                QUITTING.store(true, Ordering::SeqCst);
                handle_for_quit.exit(0);
            });

            let c = control.clone();
            tauri::async_runtime::spawn(async move {
                let serving = c.clone();
                if let Err(e) = serving.serve_control().await {
                    c.log(format!("控制接口启动失败：{e}"));
                }
            });

            setup_tray(app)?;

            if let Some(win) = app.get_webview_window("main") {
                // 点 X 只是隐藏到托盘，代理继续跑
                let w = win.clone();
                let core_for_log = control.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        if !QUITTING.load(Ordering::SeqCst) {
                            api.prevent_close();
                            let _ = w.hide();
                            core_for_log.log("窗口已隐藏到托盘（托盘菜单「退出」可真正退出）");
                        }
                    }
                });
                // 核心随程序无感启动：普通启动和开机自启都直接静默起核心。
                // 只有开机自启才隐藏窗口（静默驻留托盘）；核心本身不碰系统代理 ——
                // 接管要用户点「开启系统代理」（或托盘菜单），见 start_core_impl。
                if launched_by_autostart() {
                    let _ = win.hide();
                }
                let boot_core = control.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = start_core_impl(&boot_core).await {
                        // 没账号 / 没登录时属于正常情况（等用户填完账号再点「开启系统代理」），
                        // 界面会把这句原因显示在顶部横幅里。
                        boot_core.log(format!("启动核心失败：{e}"));
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("Tauri 初始化失败");

    let shutdown_core = core.clone();
    app.run(move |_handle, event| {
        if let tauri::RunEvent::Exit = event {
            QUITTING.store(true, Ordering::SeqCst);
            shutdown_core.shutdown();
        }
    });
}
