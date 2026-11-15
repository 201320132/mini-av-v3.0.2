// Mini AV - application logic shared by the Windows window (main.rs) and the Linux/dev host (devhost.rs).
// Pure std: it talks to the UI through `sink` (a function that delivers a JavaScript snippet) and
// receives commands through `handle`.
use crate::engine::*;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

pub struct Item {
    pub t: Threat,
    pub state: &'static str,
}

pub struct App {
    sink: Box<dyn Fn(String) + Send + Sync>,
    store: Store,
    items: Mutex<Vec<Item>>,
    cancel: AtomicBool,
    scanning: AtomicBool,
    settings: Mutex<HashMap<String, String>>,
    hashes: HashMap<String, String>,
    rules: Rules,
    excl: Mutex<Vec<String>>,
}

impl App {
    pub fn new(sink: Box<dyn Fn(String) + Send + Sync>) -> Arc<App> {
        Arc::new(App {
            sink,
            store: Store::default_store(),
            items: Mutex::new(Vec::new()),
            cancel: AtomicBool::new(false),
            scanning: AtomicBool::new(false),
            settings: Mutex::new(load_kv(&app_dir().join("settings.txt"))),
            hashes: load_signatures(),
            rules: Rules::load(),
            excl: Mutex::new(load_exclusions()),
        })
    }

    #[allow(dead_code)]
    pub fn cancel_all(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn js(&self, name: &str, json: &str) {
        (self.sink)(format!("window.AV&&window.AV.on({},{})", jstr(name), json));
    }
    fn tmsg(&self, key: &str, cls: &str) {
        self.js("tmsg", &format!("{{\"key\":{},\"cls\":{}}}", jstr(key), jstr(cls)));
    }
    fn setting(&self, k: &str, default: &str) -> String {
        self.settings.lock().unwrap().get(k).cloned().unwrap_or_else(|| default.to_string())
    }
    fn set(&self, k: &str, v: &str) {
        let mut s = self.settings.lock().unwrap();
        s.insert(k.to_string(), v.to_string());
        save_kv(&app_dir().join("settings.txt"), &s);
    }
    fn status(&self, id: u64, state: &str, msg: &str) {
        self.js("status", &format!("{{\"ids\":[{id}],\"state\":{},\"msg\":{}}}", jstr(state), jstr(msg)));
    }
    fn send_qlist(&self) {
        let items: Vec<String> = self.store.list().iter().map(|q| q.json()).collect();
        self.js("qlist", &format!("[{}]", items.join(",")));
    }
    fn send_excl(&self) {
        let v: Vec<String> = self.excl.lock().unwrap().iter().map(|s| jstr(s)).collect();
        self.js("excl", &format!("[{}]", v.join(",")));
    }
    fn send_rules(&self) {
        self.js(
            "rules",
            &format!(
                "{{\"count\":{},\"version\":{},\"custom\":{}}}",
                self.rules.count(),
                jstr(&self.rules.version()),
                self.rules.sources.len() > 1
            ),
        );
    }
    fn send_dstatus(&self) {
        let kv = defender_status();
        let body: Vec<String> = kv.iter().map(|(k, v)| format!("{}:{}", jstr(k), jstr(v))).collect();
        self.js("dstatus", &format!("{{{}}}", body.join(",")));
    }

    /// Quarantine / fix the given detections. Returns how many succeeded.
    fn apply(&self, ids: &[u64]) -> usize {
        let mut ok = 0;
        for id in ids {
            let t = {
                let items = self.items.lock().unwrap();
                match items.iter().find(|i| i.t.id == *id && i.state == "found") {
                    Some(i) => i.t.clone(),
                    None => continue,
                }
            };
            let (state, msg): (&'static str, String) = match self.store.quarantine(&t) {
                Ok(m) => {
                    ok += 1;
                    (
                        match m.as_str() {
                            "quarantined" => "quarantined",
                            "restored" => "restored",
                            _ => "fixed",
                        },
                        String::new(),
                    )
                }
                Err(e) => ("failed", e),
            };
            if let Some(i) = self.items.lock().unwrap().iter_mut().find(|i| i.t.id == *id) {
                i.state = state;
            }
            self.status(*id, state, &msg);
        }
        ok
    }
}

fn parse_ids(s: &str) -> Vec<u64> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

fn start_scan(app: &Arc<App>, mode: &str, defender: bool, paths: &str) {
    if app.scanning.swap(true, Ordering::SeqCst) {
        return;
    }
    app.cancel.store(false, Ordering::SeqCst);
    app.items.lock().unwrap().clear();
    let mode = match mode {
        "full" => Mode::Full,
        "custom" => Mode::Custom,
        _ => Mode::Quick,
    };
    let paths: Vec<PathBuf> = if mode == Mode::Custom {
        paths.split('\u{1}').map(str::trim).filter(|p| !p.is_empty()).map(PathBuf::from).collect()
    } else {
        Vec::new()
    };
    let opts = ScanOpts {
        mode,
        paths,
        defender,
        trust: app.setting("trust", "1") == "1",
        second: app.setting("second", "1") == "1",
    };
    let app = app.clone();
    thread::spawn(move || {
        let excl = app.excl.lock().unwrap().clone();
        let sum = {
            let a = app.clone();
            let mut emit = move |e: Event| match e {
                Event::Phase(p) => a.js("phase", &jstr(p)),
                Event::Progress { scanned, current } => {
                    a.js("progress", &format!("{{\"n\":{},\"cur\":{}}}", scanned, jstr(&current)))
                }
                Event::Found(t) => {
                    a.js("found", &t.json());
                    a.items.lock().unwrap().push(Item { t, state: "found" });
                }
                Event::Log(_) => {}
            };
            run_scan(&opts, &app.rules, &app.cancel, &app.hashes, &excl, &mut emit)
        };
        // quarantine confirmed threats automatically (never the "suspicious" ones)
        let mut auto = 0;
        if app.setting("autoq", "1") == "1" && !sum.cancelled {
            let ids: Vec<u64> = app
                .items
                .lock()
                .unwrap()
                .iter()
                .filter(|i| i.state == "found" && i.t.sev == Sev::High && !i.t.handled)
                .map(|i| i.t.id)
                .collect();
            auto = app.apply(&ids);
        }
        let now = now_secs();
        app.set("last_time", &now.to_string());
        app.set("last_high", &sum.high.to_string());
        app.set("last_medium", &sum.medium.to_string());
        app.js(
            "done",
            &format!(
                "{{\"scanned\":{},\"high\":{},\"medium\":{},\"info\":{},\"cancelled\":{},\"defender\":{},\"time\":{},\"auto\":{},\"trusted\":{}}}",
                sum.scanned, sum.high, sum.medium, sum.info, sum.cancelled, sum.defender_ran, now, auto, sum.trusted
            ),
        );
        app.scanning.store(false, Ordering::SeqCst);
    });
}

fn kill_all(app: &Arc<App>) {
    let app = app.clone();
    thread::spawn(move || {
        let todo: Vec<Threat> = app
            .items
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.state == "found" && i.t.sev == Sev::High && !i.t.handled)
            .map(|i| i.t.clone())
            .collect();
        let has_work = !todo.is_empty() || !app.store.list().is_empty();
        // safety net: a Windows restore point first (needs administrator rights; skipped otherwise)
        let rp = has_work && is_admin() && create_restore_point();
        audit(&format!("KILL-ALL start: {} detections, restore point: {rp}", todo.len()));
        if todo.iter().any(|t| t.kind == "defender") {
            let _ = powershell("Remove-MpThreat -ErrorAction SilentlyContinue");
        }
        let (mut ok, mut fail) = (0usize, 0usize);
        for t in todo {
            match app.store.destroy(&t) {
                Ok(_) => {
                    ok += 1;
                    if let Some(i) = app.items.lock().unwrap().iter_mut().find(|i| i.t.id == t.id) {
                        i.state = "deleted";
                    }
                    app.status(t.id, "deleted", "");
                }
                Err(e) => {
                    fail += 1;
                    if let Some(i) = app.items.lock().unwrap().iter_mut().find(|i| i.t.id == t.id) {
                        i.state = "failed";
                    }
                    app.status(t.id, "failed", &e);
                }
            }
        }
        let (qo, qf) = app.store.delete_all();
        audit(&format!("KILL-ALL done: ok {}, failed {}", ok + qo, fail + qf));
        app.js("killdone", &format!("{{\"ok\":{},\"fail\":{},\"rp\":{}}}", ok + qo, fail + qf, rp));
    });
}

pub fn handle(app: &Arc<App>, msg: &str) {
    let mut it = msg.split('\t');
    let cmd = it.next().unwrap_or("");
    let a: Vec<&str> = it.collect();
    let arg = |i: usize| a.get(i).copied().unwrap_or("");
    match cmd {
        "init" => {
            let app = app.clone();
            thread::spawn(move || {
                let drives: Vec<String> = list_drives()
                    .iter()
                    .map(|d| format!("{{\"root\":{},\"removable\":{},\"system\":{}}}", jstr(&d.root), d.removable, d.system))
                    .collect();
                let last = match app.setting("last_time", "").parse::<u64>() {
                    Ok(t) => format!(
                        "{{\"time\":{},\"high\":{},\"medium\":{}}}",
                        t,
                        app.setting("last_high", "0").parse::<u64>().unwrap_or(0),
                        app.setting("last_medium", "0").parse::<u64>().unwrap_or(0)
                    ),
                    Err(_) => "null".into(),
                };
                let excl: Vec<String> = app.excl.lock().unwrap().iter().map(|s| jstr(s)).collect();
                app.js(
                    "init",
                    &format!(
                        "{{\"lang\":{},\"autoq\":{},\"defender\":{},\"admin\":{},\"drives\":[{}],\"last\":{},\"sigs\":{},\"excl\":[{}],\"qcount\":{},\"trust\":{},\"second\":{},\"rules\":{{\"count\":{},\"version\":{},\"custom\":{}}}}}",
                        jstr(&app.setting("lang", "fa")),
                        app.setting("autoq", "1") == "1",
                        app.setting("defender", "1") == "1",
                        is_admin(),
                        drives.join(","),
                        last,
                        app.hashes.len(),
                        excl.join(","),
                        app.store.list().len(),
                        app.setting("trust", "1") == "1",
                        app.setting("second", "1") == "1",
                        app.rules.count(),
                        jstr(&app.rules.version()),
                        app.rules.sources.len() > 1
                    ),
                );
            });
        }
        "dstatus" => {
            let app = app.clone();
            thread::spawn(move || app.send_dstatus());
        }
        "scan" => start_scan(app, arg(0), arg(1) == "1", arg(2)),
        "stop" => {
            app.cancel.store(true, Ordering::SeqCst);
            thread::spawn(defender_cancel);
        }
        "act" => {
            let ids = parse_ids(arg(1));
            match arg(0) {
                "ignore" => {
                    for id in ids {
                        let target = {
                            let mut items = app.items.lock().unwrap();
                            items.iter_mut().find(|i| i.t.id == id).map(|i| {
                                i.state = "ignored";
                                i.t.target.to_lowercase()
                            })
                        };
                        if let Some(tg) = target {
                            let mut ex = app.excl.lock().unwrap();
                            if !ex.contains(&tg) {
                                ex.push(tg);
                            }
                            save_exclusions(&ex);
                            drop(ex);
                            app.status(id, "ignored", "");
                        }
                    }
                    app.send_excl();
                }
                _ => {
                    let app = app.clone();
                    thread::spawn(move || {
                        app.apply(&ids);
                        app.send_qlist();
                    });
                }
            }
        }
        "qlist" => {
            let app = app.clone();
            thread::spawn(move || app.send_qlist());
        }
        "restore" => {
            let (app, id) = (app.clone(), arg(0).to_string());
            thread::spawn(move || {
                match app.store.restore(&id) {
                    Ok(_) => app.js("toast", &format!("{{\"msg\":{},\"cls\":\"ok\"}}", jstr(&tr(&app, "restored_to")))),
                    Err(e) => app.js("toast", &format!("{{\"msg\":{},\"cls\":\"bad\"}}", jstr(&e))),
                }
                app.send_qlist();
            });
        }
        "qdelete" => {
            let (app, id) = (app.clone(), arg(0).to_string());
            thread::spawn(move || {
                let _ = app.store.delete(&id);
                app.send_qlist();
            });
        }
        "killall" => kill_all(app),
        "browse" => {
            let app = app.clone();
            thread::spawn(move || {
                if let Some(p) = browse_folder() {
                    app.js("folder", &jstr(&p));
                }
            });
        }
        "elevate" => {
            let app = app.clone();
            thread::spawn(move || match relaunch_as_admin() {
                Ok(()) => std::process::exit(0),
                Err(e) => app.js("elevate", &format!("{{\"ok\":false,\"msg\":{}}}", jstr(&e))),
            });
        }
        "sigupdate" => {
            let app = app.clone();
            thread::spawn(move || match update_signatures() {
                Ok(()) => app.tmsg("updated", "ok"),
                Err(_) => app.tmsg("failed", "bad"),
            });
        }
        "rtenable" => {
            let app = app.clone();
            thread::spawn(move || {
                match enable_realtime() {
                    Ok(()) => app.tmsg("on", "ok"),
                    Err(_) => app.tmsg("failed", "bad"),
                }
                app.send_dstatus();
            });
        }
        "setopt" => {
            let (k, v) = (arg(0), arg(1));
            if ["lang", "autoq", "defender", "trust", "second"].contains(&k) {
                app.set(k, v);
            }
        }
        "settings_info" => {
            let app = app.clone();
            thread::spawn(move || {
                app.send_excl();
                app.js("sigs", &app.hashes.len().to_string());
                app.send_rules();
                app.js("admin", &format!("{{\"admin\":{}}}", is_admin()));
            });
        }
        "rmexcl" => {
            let mut ex = app.excl.lock().unwrap();
            ex.retain(|e| e != arg(0));
            save_exclusions(&ex);
            drop(ex);
            app.send_excl();
        }
        _ => {}
    }
}

/// Tiny server-side translation used only for toasts that originate in Rust.
fn tr(app: &App, key: &str) -> String {
    let fa = app.setting("lang", "fa") == "fa";
    match (key, fa) {
        ("restored_to", true) => "بازیابی شد".into(),
        ("restored_to", false) => "Restored".into(),
        _ => key.into(),
    }
}

