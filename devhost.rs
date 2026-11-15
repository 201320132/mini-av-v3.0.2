// Mini AV - Linux / developer host (no external crates).
//
// Runs the REAL engine and command handling (app.rs + engine.rs) and serves the same UI (ui/index.html)
// over http://127.0.0.1:<port>, so the program can be run and tested on Linux or macOS with any browser.
// Windows-only features (Microsoft Defender, UAC, signature checks, registry) simply report "unavailable".
//
// Build:  rustc --edition 2021 -O src/devhost.rs -o mini-av-linux
// Run:    ./mini-av-linux [port]        then open the printed address.
//
// Security: listens on the loopback interface only, rejects foreign Host headers (DNS rebinding) and
// requires a custom header on every call (cross-site requests cannot set it).

mod app;
mod engine;

use engine::jstr;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

const HTML: &str = include_str!("../ui/index.html");

const SHIM: &str = "<script>window.ipc={postMessage:function(m){fetch('/ipc',{method:'POST',headers:{'X-MiniAV':'1'},body:m}).catch(function(){});}};\
(function poll(){fetch('/events',{headers:{'X-MiniAV':'1'}}).then(function(r){return r.json()}).then(function(a){a.forEach(function(s){try{(0,eval)(s)}catch(e){console.error(e)}});poll()}).catch(function(){setTimeout(poll,1000)})})();</script>";

struct Queue {
    q: Mutex<VecDeque<String>>,
    cv: Condvar,
}

fn respond(s: &mut TcpStream, code: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
}

fn serve(mut s: TcpStream, app: Arc<app::App>, queue: Arc<Queue>, port: u16) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 64 * 1024 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut rl = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (rl.next().unwrap_or(""), rl.next().unwrap_or(""));
    let header = |name: &str| -> String {
        head.lines()
            .skip(1)
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
            .unwrap_or_default()
    };
    let host = header("host");
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        return respond(&mut s, "403 Forbidden", "text/plain", b"bad host");
    }
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let page = HTML.replacen("<body>", &format!("<body>{SHIM}"), 1);
            respond(&mut s, "200 OK", "text/html; charset=utf-8", page.as_bytes());
        }
        ("GET", "/events") => {
            if header("x-miniav") != "1" {
                return respond(&mut s, "403 Forbidden", "text/plain", b"forbidden");
            }
            let mut g = queue.q.lock().unwrap();
            if g.is_empty() {
                g = queue.cv.wait_timeout(g, Duration::from_secs(20)).unwrap().0;
            }
            let items: Vec<String> = g.drain(..).map(|x| jstr(&x)).collect();
            drop(g);
            respond(&mut s, "200 OK", "application/json", format!("[{}]", items.join(",")).as_bytes());
        }
        ("POST", "/ipc") => {
            if header("x-miniav") != "1" {
                return respond(&mut s, "403 Forbidden", "text/plain", b"forbidden");
            }
            let len: usize = header("content-length").parse().unwrap_or(0);
            if len > 1_000_000 {
                return respond(&mut s, "413 Payload Too Large", "text/plain", b"too large");
            }
            let mut body = buf[header_end..].to_vec();
            while body.len() < len {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
            }
            app::handle(&app, &String::from_utf8_lossy(&body));
            respond(&mut s, "204 No Content", "text/plain", b"");
        }
        _ => respond(&mut s, "404 Not Found", "text/plain", b"not found"),
    }
}

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(8787);
    let queue = Arc::new(Queue { q: Mutex::new(VecDeque::new()), cv: Condvar::new() });
    let q2 = queue.clone();
    let app = app::App::new(Box::new(move |script| {
        q2.q.lock().unwrap().push_back(script);
        q2.cv.notify_all();
    }));
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    println!("Mini AV (Linux/dev host) is running: http://127.0.0.1:{port}");
    for conn in listener.incoming().flatten() {
        let (a, q) = (app.clone(), queue.clone());
        thread::spawn(move || serve(conn, a, q, port));
    }
}
