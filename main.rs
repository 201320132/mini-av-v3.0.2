// Mini AV - Windows window (tao + WebView2). All logic lives in app.rs / engine.rs.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod engine;

use engine::*;
use std::sync::Mutex;
use tao::{
    dpi::LogicalSize,
    event::{Event as TaoEvent, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

enum UserEvent {
    Js(String),
}

fn fatal_box(text: &str) {
    let t = text.replace('\'', "''");
    let _ = powershell(&format!(
        "Add-Type -AssemblyName System.Windows.Forms; [void][System.Windows.Forms.MessageBox]::Show('{t}','Mini AV')"
    ));
}

fn main() {
    // keep WebView2 data out of the program folder (it may be read-only)
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", app_dir().join("webview"));

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("Mini AV")
        .with_inner_size(LogicalSize::new(1080.0, 700.0))
        .with_min_inner_size(LogicalSize::new(820.0, 560.0))
        .build(&event_loop)
        .expect("window");

    let proxy = Mutex::new(proxy);
    let app = app::App::new(Box::new(move |script| {
        if let Ok(p) = proxy.lock() {
            let _ = p.send_event(UserEvent::Js(script));
        }
    }));

    let handler_app = app.clone();
    let built = WebViewBuilder::new()
        .with_html(include_str!("../ui/index.html"))
        .with_ipc_handler(move |req: wry::http::Request<String>| app::handle(&handler_app, req.body()))
        .build(&window);

    let webview = match built {
        Ok(w) => w,
        Err(e) => {
            fatal_box(&format!(
                "Mini AV could not start its window ({e}).\nInstall the Microsoft Edge WebView2 Runtime from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and try again."
            ));
            return;
        }
    };

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            TaoEvent::UserEvent(UserEvent::Js(script)) => {
                let _ = webview.evaluate_script(&script);
            }
            TaoEvent::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                app.cancel_all();
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
