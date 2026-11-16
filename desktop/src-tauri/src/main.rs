// HomeSentry desktop shell.
//
// The app IS the appliance: it starts the bundled backend (a frozen copy of the same Python
// that runs on the Linux box) on a random loopback port with a one-time session token, shows
// its UI in a native window, and keeps monitoring from the menu bar after the window closes.
// No browser, no open port beyond 127.0.0.1, nothing leaves the Mac except threat-intel pulls.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_notification::NotificationExt;

const WATCH_EVERY_MIN: &str = "30";

struct Backend {
    child: Mutex<Option<Child>>,
    port: u16,
    token: String,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("no free loopback port")
}

fn new_token() -> String {
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).expect("system RNG");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn backend_path(app: &AppHandle) -> PathBuf {
    if let Ok(p) = std::env::var("HOMESENTRY_BACKEND") {
        return PathBuf::from(p); // development: point at dist/homesentry-backend/...
    }
    let exe = if cfg!(windows) { "homesentry-backend.exe" } else { "homesentry-backend" };
    app.path()
        .resource_dir()
        .expect("resource dir")
        .join("backend")
        .join(exe)
}

/// Minimal loopback HTTP client (HTTP/1.0, so no chunked bodies). Returns the body.
fn http(port: u16, token: &str, method: &str, path: &str) -> Option<String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(15))).ok()?;
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n"
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    buf.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn stop_backend(app: &AppHandle) {
    if let Some(b) = app.try_state::<Backend>() {
        if let Some(mut c) = b.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// New medium+ timeline events become native notifications (they never leave the Mac).
fn watch_events(app: AppHandle, port: u16, token: String) {
    std::thread::spawn(move || {
        let mut since = now();
        let mut warned_lan = false;
        loop {
            std::thread::sleep(Duration::from_secs(45));
            let Some(body) = http(port, &token, "GET", &format!("/api/events?since={since:.3}"))
            else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else { continue };
            if let Some(t) = v["now"].as_f64() {
                since = t;
            }
            let evs = v["events"].as_array().cloned().unwrap_or_default();
            for e in evs.iter().take(4) {
                let title = e["title"].as_str().unwrap_or("HomeSentry");
                let sev = e["severity"].as_str().unwrap_or("");
                let body = match e["device"].as_str() {
                    Some(d) if !d.is_empty() => format!("{d} · {sev}"),
                    _ => sev.to_string(),
                };
                let _ = app.notification().builder().title(title).body(body).show();
            }
            if evs.len() > 4 {
                let _ = app
                    .notification()
                    .builder()
                    .title("HomeSentry")
                    .body(format!("{} more changes on the Timeline", evs.len() - 4))
                    .show();
            }
            if v["local_network_blocked"].as_bool() == Some(true) && !warned_lan {
                warned_lan = true;
                let _ = app
                    .notification()
                    .builder()
                    .title("HomeSentry can't see your network")
                    .body("Turn it on in System Settings → Privacy & Security → Local Network.")
                    .show();
            }
        }
    });
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let (port, token) = (free_port(), new_token());
            let logs = app.path().app_log_dir()?;
            std::fs::create_dir_all(&logs)?;
            let log = std::fs::File::create(logs.join("backend.log"))?;
            let child = Command::new(backend_path(&handle))
                .args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()])
                .args(["--watch-every", WATCH_EVERY_MIN])
                .env("HOMESENTRY_TOKEN", &token)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?;
            app.manage(Backend { child: Mutex::new(Some(child)), port, token: token.clone() });

            // wait for the backend; if it dies or never listens, say so instead of a blank window
            let deadline = Instant::now() + Duration::from_secs(45);
            let mut up = false;
            while Instant::now() < deadline {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    up = true;
                    break;
                }
                let b = app.state::<Backend>();
                let exited = b.child.lock().unwrap().as_mut().map(|c| c.try_wait());
                if matches!(exited, Some(Ok(Some(_)))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            let target = if up {
                let url = format!("http://127.0.0.1:{port}/auth?token={token}");
                WebviewUrl::External(url.parse()?)
            } else {
                WebviewUrl::App("error.html".into())
            };
            WebviewWindowBuilder::new(app, "main", target)
                .title("HomeSentry")
                .inner_size(1220.0, 880.0)
                .min_inner_size(420.0, 600.0)
                .build()?;

            let open = MenuItem::with_id(app, "open", "Open HomeSentry", true, None::<&str>)?;
            let scan = MenuItem::with_id(app, "scan", "Scan now", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit HomeSentry", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &scan, &sep, &quit])?;
            let mut tray = TrayIconBuilder::with_id("main").tooltip("HomeSentry").menu(&menu);
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.on_menu_event(|app, ev| match ev.id().as_ref() {
                "open" => show_main(app),
                "scan" => {
                    let b = app.state::<Backend>();
                    let (p, t) = (b.port, b.token.clone());
                    std::thread::spawn(move || {
                        let _ = http(p, &t, "POST", "/scan");
                    });
                }
                "quit" => {
                    stop_backend(app);
                    app.exit(0);
                }
                _ => {}
            })
            .build(app)?;

            watch_events(handle, port, token);
            Ok(())
        })
        .on_window_event(|w, ev| {
            // closing the window keeps HomeSentry watching from the menu bar
            if let WindowEvent::CloseRequested { api, .. } = ev {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start HomeSentry")
        .run(|app, ev| match ev {
            RunEvent::Exit => stop_backend(app),
            #[cfg(target_os = "macos")]
            RunEvent::Reopen { .. } => show_main(app),
            _ => {}
        });
}
