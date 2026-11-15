//! Mini AV scan engine. Pure `std`, no external crates, so it can be unit-tested anywhere.
//!
//! Safety rules built into the engine:
//!  * Only files that were reported as a threat are ever touched.
//!  * Files inside the Windows folder (except Temp) are never scanned or modified.
//!  * "Medium" detections are never removed automatically, only "High" ones.
//!  * Quarantine keeps an obfuscated copy so every action can be undone (Restore).
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ───────────────────────────── JSON helper ─────────────────────────────

pub fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{2028}' => o.push_str("\\u2028"),
            '\u{2029}' => o.push_str("\\u2029"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

// ───────────────────────────── SHA-256 ─────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    blen: usize,
    total: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buf: [0; 64],
            blen: 0,
            total: 0,
        }
    }
    fn block(&mut self, b: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = self.h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(v[i]);
        }
    }
    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.blen > 0 {
            let take = (64 - self.blen).min(data.len());
            self.buf[self.blen..self.blen + take].copy_from_slice(&data[..take]);
            self.blen += take;
            data = &data[take..];
            if self.blen == 64 {
                let b = self.buf;
                self.block(&b);
                self.blen = 0;
            }
        }
        while data.len() >= 64 {
            self.block(&data[..64]);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.blen = data.len();
        }
    }
    pub fn finish(mut self) -> String {
        let bits = self.total * 8;
        let mut pad = vec![0x80u8];
        while (self.blen + pad.len()) % 64 != 56 {
            pad.push(0);
        }
        pad.extend_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        self.h.iter().map(|x| format!("{x:08x}")).collect()
    }
}

pub fn sha256_bytes(b: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(b);
    s.finish()
}

pub fn sha256_file(p: &Path) -> Option<String> {
    let mut f = File::open(p).ok()?;
    let mut s = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        s.update(&buf[..n]);
    }
    Some(s.finish())
}

// ───────────────────────────── types ─────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sev {
    High,
    Medium,
    Info,
}
impl Sev {
    pub fn as_str(self) -> &'static str {
        match self {
            Sev::High => "high",
            Sev::Medium => "medium",
            Sev::Info => "info",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Remedy {
    File,
    Reg { key: String, name: String, typ: String, value: String },
    Hosts(Vec<String>),
    Unhide,
    /// Report-only: Mini AV never changes these by itself.
    Manual,
}

#[derive(Clone, Debug)]
pub struct Threat {
    pub id: u64,
    pub kind: &'static str,
    pub name: String,
    pub target: String,
    pub detail: String,
    pub sev: Sev,
    pub remedy: Remedy,
    pub handled: bool,
    pub confirmed: bool,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Threat {
    pub fn new(kind: &'static str, name: &str, target: String, detail: String, sev: Sev, remedy: Remedy) -> Threat {
        Threat {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            kind,
            name: name.to_string(),
            target,
            detail,
            sev,
            remedy,
            handled: false,
            confirmed: false,
        }
    }
    pub fn json(&self) -> String {
        format!(
            "{{\"id\":{},\"kind\":{},\"name\":{},\"target\":{},\"detail\":{},\"sev\":{},\"handled\":{},\"manual\":{},\"confirmed\":{}}}",
            self.id,
            jstr(self.kind),
            jstr(&self.name),
            jstr(&self.target),
            jstr(&self.detail),
            jstr(self.sev.as_str()),
            self.handled,
            matches!(self.remedy, Remedy::Manual),
            self.confirmed
        )
    }
}

pub enum Event {
    Phase(&'static str),
    Progress { scanned: u64, current: String },
    Found(Threat),
    Log(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Quick,
    Full,
    Custom,
}

pub struct ScanOpts {
    pub mode: Mode,
    pub paths: Vec<PathBuf>,
    pub defender: bool,
    /// Ask Windows (Authenticode) whether flagged files are validly signed, and skip those.
    pub trust: bool,
    /// Ask Microsoft Defender for a second opinion on suspicious files.
    pub second: bool,
}

#[derive(Default, Debug, Clone)]
pub struct Summary {
    pub scanned: u64,
    pub high: u64,
    pub medium: u64,
    pub info: u64,
    pub cancelled: bool,
    pub defender_ran: bool,
    pub trusted: u64,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    pub usb_like: bool,
    pub depth: usize,
    pub drive_root: bool,
}

// ───────────────────────────── low-level helpers ─────────────────────────────

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// Run a program without a console window and return (exit code, stdout+stderr).
pub fn run_hidden(program: &str, args: &[&str]) -> Option<(i32, String)> {
    let mut c = Command::new(program);
    c.args(args).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = c.output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some((out.status.code().unwrap_or(-1), s))
}

/// Same as `run_hidden` but can be interrupted through `cancel`.
pub fn run_cancellable(program: &str, args: &[&str], cancel: &AtomicBool) -> Option<(i32, String)> {
    let mut c = Command::new(program);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let mut child = c.spawn().ok()?;
    let mut so = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        String::from_utf8_lossy(&b).to_string()
    });
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some((st.code().unwrap_or(-1), reader.join().unwrap_or_default())),
            Ok(None) => {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some((-2, String::new()));
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            Err(_) => return None,
        }
    }
}

pub fn powershell(script: &str) -> Option<(i32, String)> {
    run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
}

const ATTR_HIDDEN: u32 = 0x2;
const ATTR_SYSTEM: u32 = 0x4;
const ATTR_REPARSE: u32 = 0x400;

fn attrs_meta(m: &fs::Metadata) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes()
    }
    #[cfg(not(windows))]
    {
        let _ = m;
        0
    }
}

fn attrs_path(p: &Path) -> u32 {
    fs::symlink_metadata(p).map(|m| attrs_meta(&m)).unwrap_or(0)
}

fn read_head(p: &Path, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max];
    match File::open(p).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

// ───────────────────────────── system info ─────────────────────────────

pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // `fltmc` only works with administrator rights
        run_hidden("fltmc", &[]).map(|(c, _)| c == 0).unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Ask Windows (UAC prompt) to start this program again with administrator rights.
pub fn relaunch_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let p = exe.to_string_lossy().replace('\'', "''");
    let (code, out) = powershell(&format!("Start-Process -FilePath '{p}' -Verb RunAs")).ok_or("PowerShell not available")?;
    if code == 0 {
        Ok(())
    } else {
        Err(out.trim().to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drive {
    pub root: String,
    pub removable: bool,
    pub system: bool,
}

pub fn list_drives() -> Vec<Drive> {
    #[cfg(windows)]
    {
        extern "system" {
            fn GetDriveTypeW(root: *const u16) -> u32;
        }
        let sys = env("SystemDrive").to_uppercase();
        let mut v = Vec::new();
        for c in b'A'..=b'Z' {
            let root = format!("{}:\\", c as char);
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            let t = unsafe { GetDriveTypeW(wide.as_ptr()) };
            let removable = match t {
                2 => true,
                3 => false,
                _ => continue, // skip network, CD-ROM, RAM disks, unknown
            };
            let system = root.to_uppercase().starts_with(&sys);
            v.push(Drive { root, removable, system });
        }
        v
    }
    #[cfg(not(windows))]
    {
        vec![Drive { root: "/".into(), removable: false, system: true }]
    }
}

fn join_env(var: &str, rest: &str) -> Option<PathBuf> {
    let b = env(var);
    if b.is_empty() {
        None
    } else {
        Some(Path::new(&b).join(rest))
    }
}

fn user_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut add = |p: Option<PathBuf>| {
        if let Some(p) = p {
            if p.is_dir() && !v.contains(&p) {
                v.push(p);
            }
        }
    };
    for sub in ["Desktop", "Downloads", "Documents"] {
        add(join_env("USERPROFILE", sub));
        add(join_env("OneDrive", sub));
    }
    add(join_env("PUBLIC", "Desktop"));
    v
}

fn startup_dirs() -> Vec<PathBuf> {
    [
        join_env("APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        join_env("ProgramData", "Microsoft\\Windows\\Start Menu\\Programs\\StartUp"),
    ]
    .into_iter()
    .flatten()
    .filter(|p| p.is_dir())
    .collect()
}

fn temp_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    for p in [Some(std::env::temp_dir()), join_env("LOCALAPPDATA", "Temp"), join_env("SystemRoot", "Temp")]
        .into_iter()
        .flatten()
    {
        if p.is_dir() && !v.contains(&p) {
            v.push(p);
        }
    }
    v
}

pub fn quick_targets(drives: &[Drive]) -> Vec<Target> {
    let mut t = Vec::new();
    let mut add = |path: PathBuf, usb: bool, depth: usize, root: bool| t.push(Target { path, usb_like: usb, depth, drive_root: root });
    for d in drives.iter().filter(|d| d.removable) {
        add(PathBuf::from(&d.root), true, 64, true);
    }
    for d in drives.iter().filter(|d| !d.removable && !d.system) {
        add(PathBuf::from(&d.root), true, 1, true);
    }
    for p in user_dirs() {
        add(p, false, 4, false);
    }
    for p in startup_dirs() {
        add(p, false, 2, false);
    }
    for p in temp_dirs() {
        add(p, false, 3, false);
    }
    for var in ["APPDATA", "LOCALAPPDATA"] {
        let b = env(var);
        if !b.is_empty() && Path::new(&b).is_dir() {
            add(PathBuf::from(b), false, 3, false);
        }
    }
    t
}

pub fn full_targets(drives: &[Drive]) -> Vec<Target> {
    drives
        .iter()
        .map(|d| Target { path: PathBuf::from(&d.root), usb_like: !d.system, depth: 64, drive_root: true })
        .collect()
}

pub fn custom_targets(paths: &[PathBuf], drives: &[Drive]) -> Vec<Target> {
    paths
        .iter()
        .map(|p| {
            let lp = lower(p);
            let usb = drives
                .iter()
                .any(|d| (d.removable || !d.system) && lp.starts_with(&d.root.to_lowercase()));
            Target { path: p.clone(), usb_like: usb, depth: 64, drive_root: p.parent().is_none() }
        })
        .collect()
}

// ───────────────────────────── heuristic rules ─────────────────────────────

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// The heuristics file that ships inside the program (see heuristics.txt).
pub const DEFAULT_RULES: &str = include_str!("../heuristics.txt");

/// Detection rules loaded from `heuristics.txt`. The file can be overridden or extended by the user,
/// but it can only widen what is inspected: protection of Windows folders is hard-coded elsewhere.
#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub lists: HashMap<String, Vec<String>>,
    pub settings: HashMap<String, String>,
    pub sources: Vec<String>,
}

impl Rules {
    pub fn parse_into(&mut self, text: &str) {
        let mut section = String::new();
        for raw in text.lines() {
            let l = raw.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if l.starts_with('[') && l.ends_with(']') {
                let mut name = l[1..l.len() - 1].trim().to_lowercase();
                let append = name.ends_with('+');
                if append {
                    name.pop();
                }
                if append {
                    self.lists.entry(name.clone()).or_default();
                } else {
                    self.lists.insert(name.clone(), Vec::new());
                }
                section = name;
                continue;
            }
            if section.is_empty() {
                continue;
            }
            if section == "settings" {
                if let Some((k, v)) = l.split_once('=') {
                    self.settings.insert(k.trim().to_lowercase(), v.trim().to_string());
                }
                continue;
            }
            let items: Vec<String> = if section.ends_with("_ext") {
                l.split_whitespace().map(|s| s.trim_start_matches('.').to_lowercase()).collect()
            } else {
                vec![l.to_lowercase()]
            };
            self.lists.entry(section.clone()).or_default().extend(items);
        }
    }

    pub fn builtin() -> Rules {
        let mut r = Rules::default();
        r.parse_into(DEFAULT_RULES);
        r.sources.push("built-in".into());
        r
    }

    /// Built-in rules, then optional overrides next to the program and in %APPDATA%\MiniAV.
    /// A broken override is ignored so a bad edit can never disable the scanner.
    pub fn load() -> Rules {
        let mut r = Rules::builtin();
        let mut files = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(d) = exe.parent() {
                files.push(d.join("heuristics.txt"));
            }
        }
        files.push(app_dir().join("heuristics.txt"));
        for p in files {
            if let Ok(t) = fs::read_to_string(&p) {
                let mut cand = r.clone();
                cand.parse_into(&t);
                if cand.is_sane() {
                    cand.sources.push(p.to_string_lossy().to_string());
                    r = cand;
                }
            }
        }
        r
    }

    pub fn is_sane(&self) -> bool {
        ["exe_ext", "doc_ext", "script_ext", "launchers"].iter().all(|k| self.lists.get(*k).map(|v| !v.is_empty()).unwrap_or(false))
    }
    pub fn list(&self, name: &str) -> &[String] {
        self.lists.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn has(&self, name: &str, v: &str) -> bool {
        self.list(name).iter().any(|x| x == v)
    }
    pub fn count(&self) -> usize {
        self.lists.iter().filter(|(k, _)| k.as_str() != "settings").map(|(_, v)| v.len()).sum()
    }
    pub fn version(&self) -> String {
        self.settings.get("version").cloned().unwrap_or_else(|| "?".into())
    }
    pub fn threshold(&self) -> u32 {
        self.settings.get("script_threshold").and_then(|s| s.parse().ok()).unwrap_or(3).clamp(2, 10)
    }
}

// ───────────────────────────── trust hooks (Windows itself) ─────────────────────────────

/// Things only Windows can tell us. They are injected so the logic can be tested anywhere.
pub struct Hooks {
    /// paths -> (lowercase path -> (status, signer subject)) using Windows Authenticode.
    pub sigs: Box<dyn Fn(&[String]) -> HashMap<String, (String, String)>>,
    /// Ask Microsoft Defender about one file: Some(true) = it detects a threat, Some(false) = clean.
    pub defender_file: Box<dyn Fn(&str) -> Option<bool>>,
}

impl Hooks {
    pub fn none() -> Hooks {
        Hooks { sigs: Box::new(|_| HashMap::new()), defender_file: Box::new(|_| None) }
    }
    pub fn windows() -> Hooks {
        Hooks { sigs: Box::new(win_sigs), defender_file: Box::new(win_defender_file) }
    }
}

/// Ask Windows (Get-AuthenticodeSignature) who signed these files and whether the signature is valid.
pub fn win_sigs(paths: &[String]) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    if paths.is_empty() {
        return out;
    }
    let list = app_dir().join("sigcheck.tmp");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(paths.join("\r\n").as_bytes());
    if fs::write(&list, bytes).is_err() {
        return out;
    }
    let script = format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
         Get-Content -LiteralPath '{}' -Encoding UTF8 | ForEach-Object {{ \
           $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue; \
           if ($s) {{ \"$($s.Status)|$_|$($s.SignerCertificate.Subject)\" }} }}",
        list.to_string_lossy().replace('\'', "''")
    );
    if let Some((_, text)) = powershell(&script) {
        for l in text.lines() {
            if let Some((status, rest)) = l.trim().split_once('|') {
                if let Some((p, subj)) = rest.split_once('|') {
                    out.insert(p.to_lowercase(), (status.to_lowercase(), subj.to_string()));
                }
            }
        }
    }
    let _ = fs::remove_file(&list);
    out
}

/// One-file Microsoft Defender scan that does not remediate: exit code 0 = clean, 2 = threat.
pub fn win_defender_file(path: &str) -> Option<bool> {
    let mp = find_mpcmdrun()?;
    let (code, _) = run_hidden(&mp.to_string_lossy(), &["-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"])?;
    match code {
        0 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

// ───────────────────────────── scanner ─────────────────────────────

pub struct Scanner<'a> {
    cancel: &'a AtomicBool,
    hashes: &'a HashMap<String, String>,
    excl: &'a [String],
    rules: &'a Rules,
    hooks: Hooks,
    win: String,
    seen: HashSet<String>,
    reported: HashSet<String>,
    pending: Vec<Threat>,
    pub trust: bool,
    pub second: bool,
    pub sum: Summary,
    last_emit: Instant,
    emit: &'a mut dyn FnMut(Event),
}

fn boundary_ok(rest: &str) -> bool {
    rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/')
}

/// Pure path-protection rule (testable). `lp` is a lowercase path.
pub fn is_protected(lp: &str, win: &str, program_dirs: &[String], extra: &[String], kind: &str) -> bool {
    if !win.is_empty() && lp.starts_with(win) {
        let rest = &lp[win.len()..];
        if boundary_ok(rest) && !(rest.starts_with("\\temp") || rest.starts_with("/temp")) {
            return true;
        }
    }
    if extra.iter().any(|e| !e.is_empty() && lp.starts_with(e.as_str()) && boundary_ok(&lp[e.len()..])) {
        return true;
    }
    if !matches!(kind, "eicar" | "hash" | "defender") {
        for p in program_dirs {
            if !p.is_empty() && lp.starts_with(p.as_str()) && boundary_ok(&lp[p.len()..]) {
                return true;
            }
        }
    }
    false
}

pub fn program_dirs() -> Vec<String> {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().map(|v| env(v).to_lowercase()).filter(|s| !s.is_empty()).collect()
}

impl<'a> Scanner<'a> {
    pub fn new(
        cancel: &'a AtomicBool,
        hashes: &'a HashMap<String, String>,
        excl: &'a [String],
        rules: &'a Rules,
        emit: &'a mut dyn FnMut(Event),
    ) -> Self {
        Scanner {
            cancel,
            hashes,
            excl,
            rules,
            hooks: Hooks::none(),
            win: env("SystemRoot").to_lowercase(),
            seen: HashSet::new(),
            reported: HashSet::new(),
            pending: Vec::new(),
            trust: true,
            second: true,
            sum: Summary::default(),
            last_emit: Instant::now(),
            emit,
        }
    }

    pub fn with_hooks(mut self, h: Hooks) -> Self {
        self.hooks = h;
        self
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn emit_found(&mut self, t: Threat) {
        match t.sev {
            Sev::High => self.sum.high += 1,
            Sev::Medium => self.sum.medium += 1,
            Sev::Info => self.sum.info += 1,
        }
        (self.emit)(Event::Found(t));
    }

    /// Report right away (signature matches and non-file findings).
    fn report(&mut self, t: Threat) {
        let key = format!("{}|{}", t.kind, t.target.to_lowercase());
        if self.reported.insert(key) {
            self.emit_found(t);
        }
    }

    /// File-based heuristic findings wait until Windows has been asked whether the file is trusted.
    fn defer(&mut self, t: Threat) {
        let key = format!("{}|{}", t.kind, t.target.to_lowercase());
        if self.reported.insert(key) {
            self.pending.push(t);
        }
    }

    /// Verify deferred findings with Windows (digital signatures, Defender second opinion), then report them.
    pub fn finalize(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return;
        }
        let verify = !self.cancelled();
        let sigs = if verify && self.trust {
            let paths: Vec<String> = pending.iter().filter(|t| matches!(t.remedy, Remedy::File)).map(|t| t.target.clone()).take(400).collect();
            (self.hooks.sigs)(&paths)
        } else {
            HashMap::new()
        };
        let rules = self.rules;
        let mut budget = 25;
        for mut t in pending {
            if let Some((status, subject)) = sigs.get(&t.target.to_lowercase()) {
                if status == "valid" {
                    let subj = subject.to_lowercase();
                    let publisher_ok = rules.list("trusted_publishers").iter().any(|p| subj.contains(p.as_str()));
                    if t.sev == Sev::Medium || publisher_ok {
                        self.sum.trusted += 1;
                        (self.emit)(Event::Log(format!("Trusted (valid signature): {}", t.target)));
                        continue;
                    }
                }
            }
            if verify && self.second && t.sev == Sev::Medium && budget > 0 {
                budget -= 1;
                if let Some(true) = (self.hooks.defender_file)(&t.target) {
                    t.sev = Sev::High;
                    t.confirmed = true;
                }
            }
            self.emit_found(t);
        }
    }

    fn excluded(&self, lp: &str) -> bool {
        self.excl.iter().any(|e| lp == e || lp.starts_with(&format!("{e}\\")) || lp.starts_with(&format!("{e}/")))
    }

    fn in_windows_dir(&self, lp: &str) -> bool {
        is_protected(lp, &self.win, &[], &[], "")
    }

    fn tick(&mut self, cur: &Path) {
        self.sum.scanned += 1;
        if self.sum.scanned % 32 == 0 && self.last_emit.elapsed() > Duration::from_millis(200) {
            self.last_emit = Instant::now();
            (self.emit)(Event::Progress { scanned: self.sum.scanned, current: cur.to_string_lossy().to_string() });
        }
    }

    pub fn scan_target(&mut self, t: &Target) {
        if !t.path.exists() {
            return;
        }
        (self.emit)(Event::Log(format!("Scanning {}", t.path.display())));
        let mut stack: Vec<(PathBuf, usize)> = vec![(t.path.clone(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            if self.cancelled() {
                self.sum.cancelled = true;
                return;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for ent in rd.flatten() {
                if self.cancelled() {
                    self.sum.cancelled = true;
                    return;
                }
                let Ok(meta) = ent.metadata() else { continue };
                let path = ent.path();
                if attrs_meta(&meta) & ATTR_REPARSE != 0 || meta.file_type().is_symlink() {
                    continue; // never follow junctions / symlinks
                }
                if meta.is_dir() {
                    let lp = lower(&path);
                    if depth < t.depth
                        && !self.in_windows_dir(&lp)
                        && !lp.contains("system volume information")
                        && !self.excluded(&lp)
                    {
                        stack.push((path, depth + 1));
                    }
                } else if meta.is_file() {
                    let key = lower(&path);
                    if !self.seen.insert(key) {
                        continue;
                    }
                    self.tick(&path);
                    self.inspect(&path, &meta, t);
                }
            }
        }
        if t.usb_like {
            self.restore_hidden(t);
        }
    }

    fn inspect(&mut self, path: &Path, meta: &fs::Metadata, t: &Target) {
        let r: &'a Rules = self.rules;
        let lp = lower(path);
        if self.excluded(&lp) {
            return;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        let size = meta.len();
        let attrs = attrs_meta(meta);
        let hidden_sys = attrs & (ATTR_HIDDEN | ATTR_SYSTEM) != 0;
        let in_root = t.drive_root && path.parent() == Some(t.path.as_path());
        let target = path.to_string_lossy().to_string();
        let is_exe = r.has("exe_ext", &ext);
        let is_script = r.has("script_ext", &ext);

        // 1) EICAR standard antivirus test file
        if (68..=128).contains(&size) && contains(&read_head(path, 128), EICAR) {
            self.report(Threat::new("eicar", "EICAR-Test-File", target, "Standard antivirus test file".into(), Sev::High, Remedy::File));
            return;
        }

        // 2) autorun.inf that launches something
        if name == "autorun.inf" {
            let text = String::from_utf8_lossy(&read_head(path, 16384)).to_lowercase();
            let line = text.lines().map(str::trim).find(|l| {
                l.starts_with("open")
                    || l.starts_with("shellexecute")
                    || l.starts_with("run")
                    || (l.starts_with("shell") && l.contains("command"))
            });
            if let Some(l) = line {
                self.report(Threat::new("autorun", "Worm:Autorun.Inf", target, l.to_string(), Sev::High, Remedy::File));
            }
            return;
        }

        // 3) fake shortcut (.lnk) - the classic "shortcut virus"
        if ext == "lnk" {
            let bytes = read_head(path, 16384);
            let s: String = bytes.iter().filter(|b| **b != 0).map(|&b| b as char).collect::<String>().to_lowercase();
            let launcher = r.list("launchers").iter().any(|n| s.contains(n.as_str()));
            let hint = r.list("start_hints").iter().any(|n| s.contains(n.as_str()));
            let sibling_hidden = path
                .file_stem()
                .zip(path.parent())
                .map(|(st, par)| {
                    let d = par.join(st);
                    d.is_dir() && attrs_path(&d) & ATTR_HIDDEN != 0
                })
                .unwrap_or(false);
            let verdict = if t.usb_like && in_root && (launcher || sibling_hidden) {
                Some((Sev::High, if launcher { "Shortcut runs a script/command from an external drive" } else { "Shortcut replaces a hidden folder with the same name" }))
            } else if t.usb_like && sibling_hidden {
                Some((Sev::High, "Shortcut replaces a hidden folder with the same name"))
            } else if launcher && hint {
                Some((Sev::Medium, "Shortcut starts a command or script"))
            } else {
                None
            };
            if let Some((sev, why)) = verdict {
                self.report(Threat::new("shortcut", "Heur:Shortcut.FakeLNK", target, why.into(), sev, Remedy::File));
            }
            return;
        }

        // 4) double extension: invoice.pdf.exe
        if is_exe || is_script {
            let stem = Path::new(&name).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            if let Some(inner) = Path::new(&stem).extension().map(|e| e.to_string_lossy().to_string()) {
                if r.has("doc_ext", &inner) {
                    self.defer(Threat::new("double_ext", "Heur:DoubleExt.Trojan", target, format!(".{inner}.{ext}"), Sev::High, Remedy::File));
                    return;
                }
            }
        }

        // 5) a program pretending to be a document / picture (MZ header)
        if r.has("doc_ext", &ext) && size >= 64 && read_head(path, 2) == b"MZ" {
            self.defer(Threat::new("disguised", "Heur:Disguised.Executable", target, format!(".{ext}"), Sev::High, Remedy::File));
            return;
        }

        // 6) known-bad hash list
        if r.has("hash_ext", &ext) && size > 0 && size <= 64 * 1024 * 1024 {
            if let Some(h) = sha256_file(path) {
                if let Some(n) = self.hashes.get(&h) {
                    self.report(Threat::new("hash", n, target, h, Sev::High, Remedy::File));
                    return;
                }
            }
        }

        // 7) droppers in the root of USB / external drives
        if t.usb_like && in_root {
            let dir_twin = path.file_stem().zip(path.parent()).map(|(s, p)| p.join(s).is_dir()).unwrap_or(false);
            let why = if r.has("usb_script_ext", &ext) {
                Some("Script or launcher in the root of an external drive")
            } else if is_exe && hidden_sys {
                Some("Hidden program in the root of an external drive")
            } else if ext == "exe" && dir_twin {
                Some("Program with the same name as a folder")
            } else {
                None
            };
            if let Some(w) = why {
                self.defer(Threat::new("dropper", "Heur:USB.Dropper", target, w.into(), Sev::High, Remedy::File));
                return;
            }
        }

        // 8) old-style RECYCLER trick
        if ["exe", "dll", "scr", "vbs", "bat", "com", "pif"].contains(&ext.as_str())
            && (lp.contains("\\recycler\\") || lp.contains("\\recycled\\"))
        {
            self.defer(Threat::new("recycler", "Worm:Recycler.Dropper", target, "Program hidden in a RECYCLER folder".into(), Sev::High, Remedy::File));
            return;
        }

        // 9) lower-confidence indicators (never removed automatically)
        let in_startup = lp.contains("\\start menu\\programs\\startup\\");
        let in_temp = lp.contains("\\appdata\\local\\temp\\") || lp.contains("\\windows\\temp\\");
        if in_startup && (is_exe || is_script) {
            self.defer(Threat::new("startup_file", "Heur:Startup.Item", target, "Program or script in a Startup folder".into(), Sev::Medium, Remedy::File));
            return;
        }
        if in_temp && r.has("usb_script_ext", &ext) {
            self.defer(Threat::new("dropper", "Heur:Temp.Script", target, "Script in a Temp folder".into(), Sev::Medium, Remedy::File));
            return;
        }
        if hidden_sys && (ext == "exe" || ext == "scr" || ext == "com") && !self.in_windows_dir(&lp) {
            self.defer(Threat::new("hidden_exe", "Heur:Hidden.Executable", target, "Hidden system program".into(), Sev::Medium, Remedy::File));
            return;
        }
        if matches!(ext.as_str(), "bat" | "cmd" | "ps1" | "vbs" | "js" | "hta" | "wsf") && size > 0 && size <= 512 * 1024 {
            let text = String::from_utf8_lossy(&read_head(path, 512 * 1024)).to_lowercase();
            let (score, ransom) = script_score(&text);
            if ransom || score >= r.threshold() {
                let name = if ransom { "Heur:Script.Ransomware" } else { "Heur:Script.Suspicious" };
                self.defer(Threat::new("script", name, target, format!("{score} suspicious command patterns"), Sev::Medium, Remedy::File));
            }
        }
    }

    /// After a fake-shortcut virus was found on a drive, list what it hid so it can be made visible again.
    fn restore_hidden(&mut self, t: &Target) {
        if !t.drive_root {
            return;
        }
        let r: &'a Rules = self.rules;
        let root_l = lower(&t.path);
        if !self.reported.iter().any(|k| k.starts_with("shortcut|") && k[9..].starts_with(&root_l)) {
            return;
        }
        let Ok(rd) = fs::read_dir(&t.path) else { return };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_lowercase();
            if r.has("system_names", &n) {
                continue;
            }
            let p = e.path();
            if attrs_path(&p) & ATTR_HIDDEN != 0 {
                self.report(Threat::new(
                    "hidden_data",
                    "Recovered:HiddenData",
                    p.to_string_lossy().to_string(),
                    if p.is_dir() { "folder".into() } else { "file".into() },
                    Sev::Info,
                    Remedy::Unhide,
                ));
            }
        }
    }

    /// Registry Run keys, the hosts file and other system persistence points. Report-only items use
    /// `Remedy::Manual`: Mini AV never changes them by itself.
    pub fn scan_system(&mut self, removable: &[String]) {
        (self.emit)(Event::Phase("startup"));
        for key in [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ] {
            let Some((_, out)) = run_hidden("reg", &["query", key]) else { continue };
            for (name, typ, value) in parse_reg_values(&out) {
                if let Some(sev) = judge_run_value(&value, removable) {
                    self.report(Threat::new(
                        "startup_reg",
                        "Heur:Startup.Registry",
                        format!("{key}\\{name}"),
                        value.clone(),
                        sev,
                        Remedy::Reg { key: key.to_string(), name, typ, value },
                    ));
                }
            }
        }
        (self.emit)(Event::Phase("hosts"));
        if let Some(h) = join_env("SystemRoot", "System32\\drivers\\etc\\hosts") {
            if let Ok(text) = fs::read_to_string(&h) {
                let bad = hosts_bad_lines(&text, self.rules.list("hosts_keys"));
                if !bad.is_empty() {
                    self.report(Threat::new("hosts", "Heur:Hosts.Tampering", h.to_string_lossy().to_string(), bad.join(" | "), Sev::Medium, Remedy::Hosts(bad)));
                }
            }
        }
        (self.emit)(Event::Phase("system"));
        self.scan_tasks();
        self.scan_winlogon();
        self.scan_ifeo();
        self.scan_defender_exclusions();
    }

    fn scan_tasks(&mut self) {
        let Some((_, out)) = run_hidden("schtasks", &["/query", "/fo", "CSV", "/v", "/nh"]) else { return };
        for line in out.lines() {
            let cols = parse_csv_line(line);
            if cols.len() < 9 {
                continue;
            }
            let (name, cmd) = (cols[1].clone(), cols[8].clone());
            if name.to_lowercase().starts_with("\\microsoft\\") || judge_run_value(&cmd, &[]).is_none() {
                continue;
            }
            self.report(Threat::new("task", "Heur:Task.Suspicious", name, cmd, Sev::Medium, Remedy::Manual));
        }
    }

    fn scan_winlogon(&mut self) {
        let key = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        let Some((_, out)) = run_hidden("reg", &["query", key]) else { return };
        for (name, _, value) in parse_reg_values(&out) {
            if judge_winlogon(&name, &value) {
                self.report(Threat::new("winlogon", "Heur:Winlogon.Tampering", format!("{key}\\{name}"), value, Sev::Medium, Remedy::Manual));
            }
        }
    }

    fn scan_ifeo(&mut self) {
        let key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        let Some((_, out)) = run_hidden("reg", &["query", key, "/s", "/v", "Debugger"]) else { return };
        for (k, v) in parse_ifeo(&out) {
            self.report(Threat::new("ifeo", "Heur:IFEO.Hijack", k, v, Sev::Medium, Remedy::Manual));
        }
    }

    fn scan_defender_exclusions(&mut self) {
        let Some((_, out)) = powershell("(Get-MpPreference).ExclusionPath") else { return };
        for l in out.lines().map(str::trim).filter(|l| !l.is_empty() && !l.to_lowercase().starts_with("n/a")) {
            if judge_exclusion(l) {
                self.report(Threat::new("defexcl", "Heur:Defender.WideExclusion", l.to_string(), "Microsoft Defender exclusion".into(), Sev::Medium, Remedy::Manual));
            }
        }
    }
}

// ───────────────────────────── pure judging helpers (unit-tested) ─────────────────────────────

pub fn parse_reg_values(out: &str) -> Vec<(String, String, String)> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(i) = line.find("    REG_") else { continue };
        let name = line[..i].trim().to_string();
        let rest = &line[i + 4..];
        let mut it = rest.splitn(2, "    ");
        let typ = it.next().unwrap_or("REG_SZ").trim().to_string();
        let value = it.next().unwrap_or("").trim().to_string();
        v.push((name, typ, value));
    }
    v
}

pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => cols.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    cols.push(cur);
    cols
}

pub fn judge_winlogon(name: &str, value: &str) -> bool {
    let v = value.trim().to_lowercase();
    match name.to_lowercase().as_str() {
        "shell" => v != "explorer.exe",
        "userinit" => v.split(',').map(str::trim).filter(|s| !s.is_empty()).any(|e| !e.ends_with("\\system32\\userinit.exe")),
        _ => false,
    }
}

pub fn parse_ifeo(out: &str) -> Vec<(String, String)> {
    let mut cur = String::new();
    let mut v = Vec::new();
    for line in out.lines() {
        if line.starts_with("HKEY_") {
            cur = line.trim().to_string();
        } else if let Some(i) = line.find("    REG_") {
            let name = line[..i].trim();
            let val = line[i + 4..].splitn(2, "    ").nth(1).unwrap_or("").trim().to_string();
            let lv = val.to_lowercase();
            if name.eq_ignore_ascii_case("debugger") && !lv.is_empty() && !lv.contains("vsjitdebugger") && !lv.contains("windbg") {
                v.push((format!("{cur}\\Debugger"), val));
            }
        }
    }
    v
}

pub fn judge_exclusion(p: &str) -> bool {
    let l = p.trim().trim_end_matches('\\').to_lowercase();
    let bytes = l.as_bytes();
    (bytes.len() == 2 && bytes[1] == b':')
        || l.ends_with("\\users")
        || l.ends_with("\\windows")
        || l.contains("\\appdata\\local\\temp")
        || l.ends_with("\\windows\\temp")
        || l.ends_with("\\downloads")
}

pub fn script_score(text: &str) -> (u32, bool) {
    let has = |s: &str| text.contains(s);
    let mut n = 0;
    let checks: [bool; 11] = [
        has("-encodedcommand") || has(" -enc "),
        has("frombase64string"),
        has("downloadstring") || has("downloadfile") || has("invoke-webrequest") || has("net.webclient"),
        has("invoke-expression") || has("iex ") || has("iex("),
        has("certutil") && has("-urlcache"),
        has("bitsadmin") && has("/transfer"),
        has("mshta") && has("http"),
        has("regsvr32") && has("scrobj"),
        has("-windowstyle hidden") || has("-w hidden"),
        has("schtasks") && has("/create"),
        (has("add-mppreference") && has("exclusion")) || (has("set-mppreference") && has("disable")),
    ];
    for c in checks {
        if c {
            n += 1;
        }
    }
    let ransom = (has("vssadmin") && has("delete") && has("shadows"))
        || has("wbadmin delete")
        || (has("bcdedit") && has("recoveryenabled") && has(" no"));
    (n, ransom)
}

pub fn judge_run_value(value: &str, removable: &[String]) -> Option<Sev> {
    let lv = value.to_lowercase();
    let unq = lv.trim_matches('"');
    if lv.contains("\\recycler\\")
        || lv.contains("\\recycled\\")
        || removable.iter().any(|r| !r.is_empty() && unq.starts_with(&r.to_lowercase()))
        || [".vbs", ".vbe", ".hta", ".jse"].iter().any(|e| lv.contains(e))
    {
        return Some(Sev::High);
    }
    if lv.contains("wscript")
        || lv.contains("cscript")
        || lv.contains("mshta")
        || lv.contains("cmd.exe /c start")
        || (lv.contains("powershell") && (lv.contains("-enc") || lv.contains("hidden") || lv.contains("downloadstring")))
        || lv.contains("\\appdata\\local\\temp\\")
        || lv.contains("\\windows\\temp\\")
    {
        return Some(Sev::Medium);
    }
    None
}

pub fn hosts_bad_lines(text: &str, keys: &[String]) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            let ll = l.to_lowercase();
            keys.iter().any(|k| ll.contains(k.as_str()))
        })
        .map(|l| l.to_string())
        .collect()
}

// ───────────────────────────── signatures / settings files ─────────────────────────────

pub fn app_dir() -> PathBuf {
    let b = env("APPDATA");
    let base = if b.is_empty() { std::env::temp_dir() } else { PathBuf::from(b) };
    let d = base.join("MiniAV");
    let _ = fs::create_dir_all(&d);
    d
}

pub fn parse_signatures(text: &str, out: &mut HashMap<String, String>) {
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut it = l.splitn(2, char::is_whitespace);
        let h = it.next().unwrap_or("").to_lowercase();
        if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
            let n = it.next().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("Known.Malware");
            out.insert(h, n.to_string());
        }
    }
}

pub fn load_signatures() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(EICAR_SHA256.to_string(), "EICAR-Test-File".to_string());
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            if let Ok(t) = fs::read_to_string(d.join("signatures.txt")) {
                parse_signatures(&t, &mut m);
            }
        }
    }
    if let Ok(t) = fs::read_to_string(app_dir().join("signatures.txt")) {
        parse_signatures(&t, &mut m);
    }
    m
}

pub fn load_kv(p: &Path) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Ok(t) = fs::read_to_string(p) {
        for l in t.lines() {
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    m
}

pub fn save_kv(p: &Path, m: &HashMap<String, String>) {
    let mut keys: Vec<_> = m.keys().collect();
    keys.sort();
    let mut s = String::new();
    for k in keys {
        s.push_str(&format!("{}={}\n", k, m[k].replace('\n', " ")));
    }
    let _ = fs::write(p, s);
}

pub fn load_exclusions() -> Vec<String> {
    fs::read_to_string(app_dir().join("exclusions.txt"))
        .map(|t| t.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

pub fn save_exclusions(v: &[String]) {
    let _ = fs::write(app_dir().join("exclusions.txt"), v.join("\n"));
}

// ───────────────────────────── Microsoft Defender ─────────────────────────────

fn ver_key(p: &Path) -> Vec<u64> {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

pub fn find_mpcmdrun() -> Option<PathBuf> {
    let pd = env("ProgramData");
    let plat = Path::new(if pd.is_empty() { "C:\\ProgramData" } else { &pd }).join("Microsoft").join("Windows Defender").join("Platform");
    if let Ok(rd) = fs::read_dir(&plat) {
        let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("MpCmdRun.exe").exists()).collect();
        v.sort_by_key(|p| ver_key(p));
        if let Some(p) = v.pop() {
            return Some(p.join("MpCmdRun.exe"));
        }
    }
    let pf = env("ProgramFiles");
    let p = Path::new(if pf.is_empty() { "C:\\Program Files" } else { &pf }).join("Windows Defender").join("MpCmdRun.exe");
    p.exists().then_some(p)
}

pub fn defender_cancel() {
    if let Some(mp) = find_mpcmdrun() {
        let _ = run_hidden(&mp.to_string_lossy(), &["-Cancel"]);
    }
}

/// Let Microsoft Defender scan, then collect what it detected during this run.
pub fn defender_scan(opts: &ScanOpts, drives: &[Drive], cancel: &AtomicBool, emit: &mut dyn FnMut(Event)) -> bool {
    let started = Instant::now();
    let mut ran = false;
    match find_mpcmdrun() {
        Some(mp) => {
            let mps = mp.to_string_lossy().to_string();
            emit(Event::Log(format!("Using {mps}")));
            let mut jobs: Vec<Vec<String>> = Vec::new();
            match opts.mode {
                Mode::Quick => jobs.push(vec!["-Scan".into(), "-ScanType".into(), "1".into()]),
                Mode::Full => jobs.push(vec!["-Scan".into(), "-ScanType".into(), "2".into()]),
                Mode::Custom => {
                    for p in &opts.paths {
                        jobs.push(vec!["-Scan".into(), "-ScanType".into(), "3".into(), "-File".into(), p.to_string_lossy().to_string()]);
                    }
                }
            }
            if opts.mode != Mode::Custom {
                for d in drives.iter().filter(|d| d.removable) {
                    jobs.push(vec!["-Scan".into(), "-ScanType".into(), "3".into(), "-File".into(), d.root.clone()]);
                }
            }
            for j in jobs {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let args: Vec<&str> = j.iter().map(String::as_str).collect();
                let r = run_cancellable(&mps, &args, cancel);
                match r {
                    Some((code, _)) => {
                        ran = ran || code >= 0;
                        emit(Event::Log(format!("Defender finished: exit code {code}")));
                    }
                    None => emit(Event::Log("Defender could not be started".into())),
                }
            }
        }
        None => {
            emit(Event::Log("MpCmdRun.exe not found, using Start-MpScan".into()));
            let cmd = match opts.mode {
                Mode::Quick => "Start-MpScan -ScanType QuickScan".to_string(),
                Mode::Full => "Start-MpScan -ScanType FullScan".to_string(),
                Mode::Custom => opts
                    .paths
                    .iter()
                    .map(|p| format!("Start-MpScan -ScanType CustomScan -ScanPath '{}'", p.to_string_lossy().replace('\'', "''")))
                    .collect::<Vec<_>>()
                    .join("; "),
            };
            if let Some((c, _)) = powershell(&cmd) {
                ran = c == 0;
            }
        }
    }
    let mins = started.elapsed().as_secs() / 60 + 2;
    let script = format!(
        "$t=@{{}}; Get-MpThreat | ForEach-Object {{ $t[$_.ThreatID]=$_.ThreatName }}; \
         Get-MpThreatDetection | Where-Object {{ $_.InitialDetectionTime -ge (Get-Date).AddMinutes(-{mins}) }} | \
         ForEach-Object {{ $d=$_; foreach($r in $d.Resources){{ \"$($t[$d.ThreatID])|$r\" }} }}"
    );
    if let Some((_, out)) = powershell(&script) {
        let mut seen = HashSet::new();
        for line in out.lines() {
            let Some((name, res)) = line.trim().split_once('|') else { continue };
            let path = match res.rfind("file:_") {
                Some(i) => &res[i + 6..],
                None => continue, // registry / process resources are handled by Defender itself
            };
            if !seen.insert(path.to_lowercase()) {
                continue;
            }
            let mut t = Threat::new(
                "defender",
                if name.is_empty() { "Defender:Detection" } else { name },
                path.to_string(),
                "Detected by Microsoft Defender".into(),
                Sev::High,
                Remedy::File,
            );
            t.handled = !Path::new(path).exists();
            emit(Event::Found(t));
        }
    }
    ran
}

pub fn defender_status() -> Vec<(String, String)> {
    let script = "$s=Get-MpComputerStatus; \
        \"rt=$($s.RealTimeProtectionEnabled)\"; \"av=$($s.AntivirusEnabled)\"; \"age=$($s.AntivirusSignatureAge)\"; \
        \"ver=$($s.AntivirusSignatureVersion)\"; \"updated=$($s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'))\"; \
        Get-NetFirewallProfile | ForEach-Object { \"fw_$($_.Name)=$($_.Enabled)\" }";
    let mut v = Vec::new();
    if let Some((_, out)) = powershell(script) {
        for l in out.lines() {
            if let Some((k, val)) = l.trim().split_once('=') {
                v.push((k.to_string(), val.trim().to_string()));
            }
        }
    }
    v
}

pub fn update_signatures() -> Result<(), String> {
    match powershell("Update-MpSignature -ErrorAction Stop") {
        Some((0, _)) => Ok(()),
        Some((_, o)) => Err(o.trim().to_string()),
        None => Err("PowerShell not available".into()),
    }
}

pub fn enable_realtime() -> Result<(), String> {
    match powershell("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop") {
        Some((0, _)) => Ok(()),
        Some((_, o)) => Err(o.trim().to_string()),
        None => Err("PowerShell not available".into()),
    }
}

pub fn browse_folder() -> Option<String> {
    let s = "Add-Type -AssemblyName System.Windows.Forms; \
             $f=New-Object System.Windows.Forms.FolderBrowserDialog; \
             if($f.ShowDialog() -eq 'OK'){ $f.SelectedPath }";
    let (_, out) = run_hidden("powershell", &["-NoProfile", "-STA", "-Command", s])?;
    let p = out.trim().to_string();
    (!p.is_empty()).then_some(p)
}

// ───────────────────────────── full scan orchestration ─────────────────────────────

pub fn run_scan(
    opts: &ScanOpts,
    rules: &Rules,
    cancel: &AtomicBool,
    hashes: &HashMap<String, String>,
    excl: &[String],
    emit: &mut dyn FnMut(Event),
) -> Summary {
    let drives = list_drives();
    let targets = match opts.mode {
        Mode::Quick => quick_targets(&drives),
        Mode::Full => full_targets(&drives),
        Mode::Custom => custom_targets(&opts.paths, &drives),
    };
    let removable: Vec<String> = drives.iter().filter(|d| d.removable).map(|d| d.root.clone()).collect();
    let mut sum;
    {
        let mut sc = Scanner::new(cancel, hashes, excl, rules, emit).with_hooks(Hooks::windows());
        sc.trust = opts.trust;
        sc.second = opts.second;
        sc.emit_phase("files");
        for t in &targets {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            sc.scan_target(t);
        }
        if opts.mode != Mode::Custom && !cancel.load(Ordering::Relaxed) {
            sc.scan_system(&removable);
        }
        sc.finalize();
        sum = sc.sum.clone();
    }
    if opts.defender && !cancel.load(Ordering::Relaxed) {
        emit(Event::Phase("defender"));
        let before = sum.clone();
        let mut found_high = 0u64;
        let mut wrap = |e: Event| {
            if let Event::Found(t) = &e {
                if !t.handled {
                    found_high += 1;
                }
            }
            emit(e);
        };
        sum.defender_ran = defender_scan(opts, &drives, cancel, &mut wrap);
        sum.high = before.high + found_high;
    }
    sum.cancelled = cancel.load(Ordering::Relaxed);
    sum
}

impl<'a> Scanner<'a> {
    fn emit_phase(&mut self, p: &'static str) {
        (self.emit)(Event::Phase(p));
    }
}

// ───────────────────────────── quarantine ─────────────────────────────

const MAGIC: &[u8; 8] = b"MAVQ1\0\0\0";
const XOR: u8 = 0x5A;

#[derive(Clone, Debug)]
pub struct QItem {
    pub id: String,
    pub orig: String,
    pub name: String,
    pub kind: String,
    pub sev: String,
    pub time: u64,
    pub size: u64,
    pub sha: String,
    pub remedy: String,
    pub reg_key: String,
    pub reg_name: String,
    pub reg_typ: String,
    pub reg_val: String,
}

impl QItem {
    pub fn json(&self) -> String {
        format!(
            "{{\"id\":{},\"orig\":{},\"name\":{},\"kind\":{},\"sev\":{},\"time\":{},\"size\":{},\"remedy\":{}}}",
            jstr(&self.id), jstr(&self.orig), jstr(&self.name), jstr(&self.kind), jstr(&self.sev), self.time, self.size, jstr(&self.remedy)
        )
    }
}

pub struct Store {
    pub dir: PathBuf,
}

static QCOUNT: AtomicU64 = AtomicU64::new(0);

impl Store {
    pub fn default_store() -> Store {
        let pd = env("ProgramData");
        let base = if pd.is_empty() { app_dir() } else { PathBuf::from(pd).join("MiniAV") };
        let dir = base.join("Quarantine");
        if fs::create_dir_all(&dir).is_err() {
            let d = app_dir().join("Quarantine");
            let _ = fs::create_dir_all(&d);
            return Store { dir: d };
        }
        Store { dir }
    }

    fn new_id(&self) -> String {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        format!("{:x}{:03x}", ms, QCOUNT.fetch_add(1, Ordering::Relaxed) % 4096)
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.meta"))
    }
    fn data_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.qar"))
    }

    fn write_meta(&self, q: &QItem) {
        let mut m = HashMap::new();
        for (k, v) in [
            ("orig", &q.orig), ("name", &q.name), ("kind", &q.kind), ("sev", &q.sev), ("sha", &q.sha),
            ("remedy", &q.remedy), ("reg_key", &q.reg_key), ("reg_name", &q.reg_name), ("reg_typ", &q.reg_typ), ("reg_val", &q.reg_val),
        ] {
            m.insert(k.to_string(), v.clone());
        }
        m.insert("time".into(), q.time.to_string());
        m.insert("size".into(), q.size.to_string());
        save_kv(&self.meta_path(&q.id), &m);
    }

    pub fn list(&self) -> Vec<QItem> {
        let mut v = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "meta").unwrap_or(false) {
                    let id = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                    let m = load_kv(&p);
                    let g = |k: &str| m.get(k).cloned().unwrap_or_default();
                    v.push(QItem {
                        id,
                        orig: g("orig"),
                        name: g("name"),
                        kind: g("kind"),
                        sev: g("sev"),
                        time: g("time").parse().unwrap_or(0),
                        size: g("size").parse().unwrap_or(0),
                        sha: g("sha"),
                        remedy: g("remedy"),
                        reg_key: g("reg_key"),
                        reg_name: g("reg_name"),
                        reg_typ: g("reg_typ"),
                        reg_val: g("reg_val"),
                    });
                }
            }
        }
        v.sort_by(|a, b| b.time.cmp(&a.time));
        v
    }

    /// Never touch the Windows folder (apart from its Temp folder); Program Files is also off limits
    /// for heuristic detections (only signature matches and Defender detections may be removed there).
    fn protected(path: &Path, kind: &str) -> bool {
        let extra: Vec<String> = Rules::load().list("protected_dirs").to_vec();
        is_protected(&lower(path), &env("SystemRoot").to_lowercase(), &program_dirs(), &extra, kind)
    }

    /// Move a detected threat into quarantine (a reversible, harmless storage).
    pub fn quarantine(&self, t: &Threat) -> Result<String, String> {
        match &t.remedy {
            Remedy::File => {
                let src = Path::new(&t.target);
                if Self::protected(src, t.kind) {
                    return Err("protected".into());
                }
                let meta = fs::symlink_metadata(src).map_err(|e| e.to_string())?;
                if !meta.is_file() {
                    return Err("not a file".into());
                }
                prepare_for_delete(src);
                let id = self.new_id();
                let dst = self.data_path(&id);
                let sha = self.copy_obfuscated(src, &dst).inspect_err(|_| {
                    let _ = fs::remove_file(&dst);
                })?;
                if let Err(e) = remove_file_force(src) {
                    let _ = fs::remove_file(&dst);
                    return Err(e);
                }
                let q = QItem {
                    id: id.clone(), orig: t.target.clone(), name: t.name.clone(), kind: t.kind.into(), sev: t.sev.as_str().into(),
                    time: now_secs(), size: meta.len(), sha, remedy: "file".into(),
                    reg_key: String::new(), reg_name: String::new(), reg_typ: String::new(), reg_val: String::new(),
                };
                self.write_meta(&q);
                audit(&format!("QUARANTINE {} [{}] {}", t.target, t.name, t.kind));
                Ok("quarantined".into())
            }
            Remedy::Reg { key, name, typ, value } => {
                reg_delete(key, name)?;
                let q = QItem {
                    id: self.new_id(), orig: t.target.clone(), name: t.name.clone(), kind: t.kind.into(), sev: t.sev.as_str().into(),
                    time: now_secs(), size: 0, sha: String::new(), remedy: "reg".into(),
                    reg_key: key.clone(), reg_name: name.clone(), reg_typ: typ.clone(), reg_val: value.clone(),
                };
                self.write_meta(&q);
                audit(&format!("QUARANTINE {} [{}] {}", t.target, t.name, t.kind));
                Ok("quarantined".into())
            }
            Remedy::Hosts(lines) => fix_hosts(&t.target, &self.dir, lines).map(|_| "fixed".into()),
            Remedy::Unhide => unhide(&t.target).map(|_| "restored".into()),
            Remedy::Manual => Err("manual".into()),
        }
    }

    /// Delete a detected threat directly (used by "Kill all viruses").
    pub fn destroy(&self, t: &Threat) -> Result<String, String> {
        let r = self.destroy_inner(t);
        audit(&format!("DESTROY {} [{}] -> {:?}", t.target, t.name, r));
        r
    }

    fn destroy_inner(&self, t: &Threat) -> Result<String, String> {
        match &t.remedy {
            Remedy::File => {
                let src = Path::new(&t.target);
                if Self::protected(src, t.kind) {
                    return Err("protected".into());
                }
                if fs::symlink_metadata(src).is_err() {
                    return Ok("deleted".into());
                }
                prepare_for_delete(src);
                remove_file_force(src).map(|_| "deleted".into())
            }
            Remedy::Reg { key, name, .. } => reg_delete(key, name).map(|_| "deleted".into()),
            Remedy::Hosts(lines) => fix_hosts(&t.target, &self.dir, lines).map(|_| "fixed".into()),
            Remedy::Unhide => unhide(&t.target).map(|_| "restored".into()),
            Remedy::Manual => Err("manual".into()),
        }
    }

    fn copy_obfuscated(&self, src: &Path, dst: &Path) -> Result<String, String> {
        let mut r = File::open(src).map_err(|e| e.to_string())?;
        let mut w = File::create(dst).map_err(|e| e.to_string())?;
        w.write_all(MAGIC).map_err(|e| e.to_string())?;
        let mut sha = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            sha.update(&buf[..n]);
            for b in &mut buf[..n] {
                *b ^= XOR;
            }
            w.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        }
        w.flush().map_err(|e| e.to_string())?;
        let _ = w.sync_all();
        Ok(sha.finish())
    }

    pub fn restore(&self, id: &str) -> Result<String, String> {
        let m = load_kv(&self.meta_path(id));
        let g = |k: &str| m.get(k).cloned().unwrap_or_default();
        if g("remedy") == "reg" {
            reg_add(&g("reg_key"), &g("reg_name"), &g("reg_typ"), &g("reg_val"))?;
            let _ = fs::remove_file(self.meta_path(id));
            audit(&format!("RESTORE registry {}", g("orig")));
            return Ok(g("orig"));
        }
        let mut dest = PathBuf::from(g("orig"));
        if dest.as_os_str().is_empty() {
            return Err("missing metadata".into());
        }
        if dest.exists() {
            let n = format!("{}.restored", dest.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
            dest.set_file_name(n);
        }
        if let Some(p) = dest.parent() {
            let _ = fs::create_dir_all(p);
        }
        let mut r = File::open(self.data_path(id)).map_err(|e| e.to_string())?;
        let mut head = [0u8; 8];
        r.read_exact(&mut head).map_err(|e| e.to_string())?;
        if &head != MAGIC {
            return Err("corrupt quarantine file".into());
        }
        let mut w = File::create(&dest).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            for b in &mut buf[..n] {
                *b ^= XOR;
            }
            w.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        }
        let _ = fs::remove_file(self.data_path(id));
        let _ = fs::remove_file(self.meta_path(id));
        audit(&format!("RESTORE {}", dest.display()));
        Ok(dest.to_string_lossy().to_string())
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        audit(&format!("DELETE quarantined {id}"));
        let _ = fs::remove_file(self.data_path(id));
        fs::remove_file(self.meta_path(id)).map_err(|e| e.to_string())
    }

    pub fn delete_all(&self) -> (usize, usize) {
        let (mut ok, mut bad) = (0, 0);
        for q in self.list() {
            if self.delete(&q.id).is_ok() {
                ok += 1;
            } else {
                bad += 1;
            }
        }
        (ok, bad)
    }
}

fn prepare_for_delete(p: &Path) {
    #[cfg(windows)]
    {
        let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if ["exe", "scr", "com", "pif"].contains(&ext.as_str()) {
            let esc = p.to_string_lossy().replace('\'', "''");
            let _ = powershell(&format!(
                "Get-Process | Where-Object {{ $_.Path -eq '{esc}' }} | Stop-Process -Force -ErrorAction SilentlyContinue"
            ));
        }
        let _ = run_hidden("attrib", &["-r", "-s", "-h", &p.to_string_lossy()]);
    }
    if let Ok(m) = fs::metadata(p) {
        let mut perm = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = fs::set_permissions(p, perm);
    }
}

fn remove_file_force(p: &Path) -> Result<(), String> {
    match fs::remove_file(p) {
        Ok(_) => Ok(()),
        Err(e) => {
            #[cfg(windows)]
            {
                let _ = run_hidden("cmd", &["/C", "del", "/F", "/Q", "/A", &p.to_string_lossy()]);
                if fs::symlink_metadata(p).is_err() {
                    return Ok(());
                }
            }
            Err(e.to_string())
        }
    }
}

pub fn unhide(path: &str) -> Result<(), String> {
    match run_hidden("attrib", &["-h", "-s", "-r", path, "/s", "/d"]) {
        Some((0, _)) => Ok(()),
        Some((_, o)) => Err(o.trim().to_string()),
        None => Err("attrib not available".into()),
    }
}

fn reg_delete(key: &str, name: &str) -> Result<(), String> {
    match run_hidden("reg", &["delete", key, "/v", name, "/f"]) {
        Some((0, _)) => Ok(()),
        Some((_, o)) => Err(o.trim().to_string()),
        None => Err("reg not available".into()),
    }
}

fn reg_add(key: &str, name: &str, typ: &str, val: &str) -> Result<(), String> {
    match run_hidden("reg", &["add", key, "/v", name, "/t", typ, "/d", val, "/f"]) {
        Some((0, _)) => Ok(()),
        Some((_, o)) => Err(o.trim().to_string()),
        None => Err("reg not available".into()),
    }
}

/// Back up the hosts file, then drop only the lines that were shown to the user as suspicious.
fn fix_hosts(path: &str, backup_dir: &Path, lines: &[String]) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let bad: HashSet<&str> = lines.iter().map(|l| l.trim()).collect();
    if bad.is_empty() {
        return Ok(());
    }
    let _ = fs::write(backup_dir.join("hosts.miniav.bak"), &text);
    let kept: Vec<&str> = text.lines().filter(|l| !bad.contains(l.trim())).collect();
    fs::write(path, kept.join("\r\n") + "\r\n").map_err(|e| e.to_string())
}

/// Append one line to the audit log (%APPDATA%\MiniAV\actions.log).
pub fn audit(line: &str) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(app_dir().join("actions.log")) {
        let _ = writeln!(f, "{} {}", now_secs(), line);
    }
}

/// Best effort Windows restore point before a big clean-up. Needs administrator rights and System Restore.
pub fn create_restore_point() -> bool {
    matches!(
        powershell("Checkpoint-Computer -Description 'Mini AV before clean-up' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop"),
        Some((0, _))
    )
}

// ───────────────────────────── tests ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mav_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_bytes(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_bytes(EICAR), EICAR_SHA256);
        let big = vec![b'a'; 1_000_000];
        assert_eq!(sha256_bytes(&big), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn json_escape() {
        assert_eq!(jstr("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn run_value_judging() {
        assert_eq!(judge_run_value("C:\\x\\a.vbs", &[]), Some(Sev::High));
        assert_eq!(judge_run_value("E:\\run.exe", &["E:\\".into()]), Some(Sev::High));
        assert_eq!(judge_run_value("\"C:\\Program Files\\OneDrive\\OneDrive.exe\" /background", &[]), None);
        assert_eq!(judge_run_value("powershell -w hidden -enc AAA", &[]), Some(Sev::Medium));
    }

    #[test]
    fn hosts_lines() {
        let t = "# c\n127.0.0.1 localhost\n0.0.0.0 www.kaspersky.com\n";
        let keys = Rules::builtin().list("hosts_keys").to_vec();
        assert_eq!(hosts_bad_lines(t, &keys), vec!["0.0.0.0 www.kaspersky.com".to_string()]);
    }

    #[test]
    fn scripts() {
        let (s, r) = script_score("vssadmin delete shadows /all");
        assert!(r && s == 0);
        let (s, _) = script_score("powershell -enc x ; downloadstring ; iex (x)");
        assert!(s >= 3);
        assert_eq!(script_score("echo hello").0, 0);
    }

    #[test]
    fn scan_finds_known_patterns_and_ignores_clean_files() {
        let d = tmp("scan");
        fs::write(d.join("eicar.txt"), EICAR).unwrap();
        fs::write(d.join("photo.jpg"), b"MZ\x90\x00 this is really a program ..................................................").unwrap();
        fs::write(d.join("report.pdf.exe"), b"not much").unwrap();
        fs::write(d.join("autorun.inf"), b"[autorun]\r\nopen=virus.exe\r\n").unwrap();
        fs::write(d.join("USB.lnk"), b"L\0\0\0 c\0m\0d\0.\0e\0x\0e\0 /c start x.vbs").unwrap();
        fs::write(d.join("run.vbs"), b"WScript.Echo 1").unwrap();
        // clean files
        fs::write(d.join("notes.txt"), b"hello world, nothing here").unwrap();
        fs::write(d.join("real.jpg"), b"\xff\xd8\xff\xe0 jpeg data ................................................................").unwrap();
        fs::write(d.join("setup.exe"), b"MZ clean program data").unwrap();
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("sub").join("deep.pdf.scr"), b"x").unwrap();

        let cancel = AtomicBool::new(false);
        let mut hashes = HashMap::new();
        hashes.insert(sha256_bytes(b"MZ evil sample"), "Test.Known".to_string());
        fs::write(d.join("evil.exe"), b"MZ evil sample").unwrap();
        let mut found: Vec<Threat> = Vec::new();
        {
            let mut emit = |e: Event| {
                if let Event::Found(t) = e {
                    found.push(t)
                }
            };
            let rules = Rules::builtin();
            let mut sc = Scanner::new(&cancel, &hashes, &[], &rules, &mut emit);
            sc.scan_target(&Target { path: d.clone(), usb_like: true, depth: 8, drive_root: true });
            sc.finalize();
            assert!(sc.sum.scanned >= 10);
        }
        let has = |kind: &str, file: &str| found.iter().any(|t| t.kind == kind && t.target.ends_with(file));
        assert!(has("eicar", "eicar.txt"), "{found:?}");
        assert!(has("disguised", "photo.jpg"));
        assert!(has("double_ext", "report.pdf.exe"));
        assert!(has("double_ext", "deep.pdf.scr"));
        assert!(has("autorun", "autorun.inf"));
        assert!(has("shortcut", "USB.lnk"));
        assert!(has("dropper", "run.vbs"));
        assert!(has("hash", "evil.exe"));
        for clean in ["notes.txt", "real.jpg", "setup.exe"] {
            assert!(!found.iter().any(|t| t.target.ends_with(clean)), "false positive: {clean}");
        }
        // no duplicates
        let mut keys = HashSet::new();
        for t in &found {
            assert!(keys.insert(format!("{}{}", t.kind, t.target)));
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn exclusions_and_cancel_work() {
        let d = tmp("excl");
        fs::write(d.join("eicar.txt"), EICAR).unwrap();
        let hashes = HashMap::new();
        let cancel = AtomicBool::new(false);
        let mut n = 0;
        {
            let ex = vec![lower(&d.join("eicar.txt"))];
            let mut emit = |e: Event| {
                if let Event::Found(_) = e {
                    n += 1
                }
            };
            let rules = Rules::builtin();
            let mut sc = Scanner::new(&cancel, &hashes, &ex, &rules, &mut emit);
            sc.scan_target(&Target { path: d.clone(), usb_like: false, depth: 3, drive_root: false });
        }
        assert_eq!(n, 0);
        let cancel2 = AtomicBool::new(true);
        let mut emit = |_e: Event| {};
        let rules = Rules::builtin();
        let mut sc = Scanner::new(&cancel2, &hashes, &[], &rules, &mut emit);
        sc.scan_target(&Target { path: d.clone(), usb_like: false, depth: 3, drive_root: false });
        assert!(sc.sum.cancelled && sc.sum.scanned == 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn quarantine_roundtrip() {
        let d = tmp("q");
        let st = Store { dir: d.join("store") };
        fs::create_dir_all(&st.dir).unwrap();
        let f = d.join("virus.exe");
        fs::write(&f, EICAR).unwrap();
        let t = Threat::new("eicar", "EICAR-Test-File", f.to_string_lossy().to_string(), String::new(), Sev::High, Remedy::File);
        assert_eq!(st.quarantine(&t).unwrap(), "quarantined");
        assert!(!f.exists(), "original must be gone");
        let items = st.list();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].sha, EICAR_SHA256);
        let stored = fs::read(st.data_path(&items[0].id)).unwrap();
        assert!(!contains(&stored, EICAR), "stored copy must be obfuscated");
        // restore
        let back = st.restore(&items[0].id).unwrap();
        assert_eq!(fs::read(&back).unwrap(), EICAR);
        assert!(st.list().is_empty());
        // quarantine again, then kill all
        let t2 = Threat::new("eicar", "EICAR-Test-File", back.clone(), String::new(), Sev::High, Remedy::File);
        st.quarantine(&t2).unwrap();
        assert_eq!(st.delete_all(), (1, 0));
        assert!(st.list().is_empty());
        assert!(fs::read_dir(&st.dir).unwrap().next().is_none());
        // direct destroy
        let g = d.join("x.exe");
        fs::write(&g, b"x").unwrap();
        let t3 = Threat::new("dropper", "x", g.to_string_lossy().to_string(), String::new(), Sev::High, Remedy::File);
        assert_eq!(st.destroy(&t3).unwrap(), "deleted");
        assert!(!g.exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn signatures_parse() {
        let mut m = HashMap::new();
        parse_signatures(&format!("# c\n{} Bad.Thing\nnothex x\n{}\n", "A".repeat(64), "b".repeat(64)), &mut m);
        assert_eq!(m.get(&"a".repeat(64)).unwrap(), "Bad.Thing");
        assert_eq!(m.get(&"b".repeat(64)).unwrap(), "Known.Malware");
        assert_eq!(m.len(), 2);
    }

    fn scan_dir_with(d: &Path, hooks: Hooks, trust: bool, second: bool) -> (Vec<Threat>, Summary) {
        let cancel = AtomicBool::new(false);
        let hashes = HashMap::new();
        let rules = Rules::builtin();
        let mut found: Vec<Threat> = Vec::new();
        let sum;
        {
            let mut emit = |e: Event| {
                if let Event::Found(t) = e {
                    found.push(t)
                }
            };
            let mut sc = Scanner::new(&cancel, &hashes, &[], &rules, &mut emit).with_hooks(hooks);
            sc.trust = trust;
            sc.second = second;
            sc.scan_target(&Target { path: d.to_path_buf(), usb_like: false, depth: 4, drive_root: false });
            sc.finalize();
            sum = sc.sum.clone();
        }
        (found, sum)
    }

    #[test]
    fn rules_builtin_sane_and_overridable() {
        let mut r = Rules::builtin();
        assert!(r.is_sane());
        assert!(r.count() > 60, "{}", r.count());
        assert_eq!(r.threshold(), 3);
        assert!(r.has("doc_ext", "pdf") && r.has("exe_ext", "exe"));
        assert!(!r.version().is_empty() && r.version() != "?");
        r.parse_into("[doc_ext+]\n.XYZ\n[hosts_keys]\nonlyone\n[settings]\nscript_threshold=99\n");
        assert!(r.has("doc_ext", "xyz") && r.has("doc_ext", "pdf"), "append keeps old items");
        assert_eq!(r.list("hosts_keys"), ["onlyone".to_string()], "replace drops old items");
        assert_eq!(r.threshold(), 10, "threshold is clamped");
        // a broken override that empties a required list is rejected by is_sane
        let mut bad = Rules::builtin();
        bad.parse_into("[exe_ext]\n");
        assert!(!bad.is_sane());
    }

    #[test]
    fn valid_signature_suppresses_false_alarms() {
        let d = tmp("trust");
        fs::write(d.join("a.pdf.exe"), b"x").unwrap(); // High, signed by Microsoft
        fs::write(d.join("b.txt.exe"), b"x").unwrap(); // High, signed by an unknown publisher
        fs::write(d.join("c.ps1"), b"powershell -enc AAA; downloadstring x; iex (y)").unwrap(); // Medium, valid signature
        fs::write(d.join("d.ps1"), b"powershell -enc AAA; downloadstring x; iex (y)").unwrap(); // Medium, unsigned
        let (a, b, c) = (lower(&d.join("a.pdf.exe")), lower(&d.join("b.txt.exe")), lower(&d.join("c.ps1")));
        let hooks = Hooks {
            sigs: Box::new(move |_| {
                let mut m = HashMap::new();
                m.insert(a.clone(), ("valid".to_string(), "CN=Microsoft Corporation, O=Microsoft Corporation".to_string()));
                m.insert(b.clone(), ("valid".to_string(), "CN=Random Ltd".to_string()));
                m.insert(c.clone(), ("valid".to_string(), "CN=Random Ltd".to_string()));
                m
            }),
            defender_file: Box::new(|_| None),
        };
        let (found, sum) = scan_dir_with(&d, hooks, true, true);
        let has = |f: &str| found.iter().any(|t| t.target.ends_with(f));
        assert!(!has("a.pdf.exe"), "Microsoft-signed file must be skipped");
        assert!(has("b.txt.exe"), "High detections are only skipped for trusted publishers");
        assert!(!has("c.ps1"), "Medium + valid signature is skipped");
        assert!(has("d.ps1"), "unsigned Medium stays");
        assert_eq!(sum.trusted, 2);
        // trust check off -> everything is reported
        let (found2, sum2) = scan_dir_with(&d, Hooks::none(), false, false);
        assert_eq!(found2.len(), 4);
        assert_eq!(sum2.trusted, 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn defender_second_opinion_upgrades_medium_only() {
        let d = tmp("second");
        fs::write(d.join("x.ps1"), b"powershell -enc AAA; downloadstring x; iex (y)").unwrap();
        fs::write(d.join("y.ps1"), b"powershell -enc AAA; downloadstring x; iex (y)").unwrap();
        let hooks = Hooks {
            sigs: Box::new(|_| HashMap::new()),
            defender_file: Box::new(|p| if p.ends_with("x.ps1") { Some(true) } else { Some(false) }),
        };
        let (found, sum) = scan_dir_with(&d, hooks, true, true);
        let x = found.iter().find(|t| t.target.ends_with("x.ps1")).unwrap();
        let y = found.iter().find(|t| t.target.ends_with("y.ps1")).unwrap();
        assert!(x.sev == Sev::High && x.confirmed);
        assert!(y.sev == Sev::Medium && !y.confirmed, "Defender 'clean' never raises or clears a finding");
        assert_eq!((sum.high, sum.medium), (1, 1));
        // second opinion off
        let hooks2 = Hooks { sigs: Box::new(|_| HashMap::new()), defender_file: Box::new(|_| Some(true)) };
        let (found2, _) = scan_dir_with(&d, hooks2, true, false);
        assert!(found2.iter().all(|t| t.sev == Sev::Medium));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn protection_rules() {
        let win = "c:\\windows";
        let pf = vec!["c:\\program files".to_string()];
        let extra = vec!["d:\\keepsafe".to_string()];
        let p = |lp: &str, kind: &str| is_protected(lp, win, &pf, &extra, kind);
        assert!(p("c:\\windows\\system32\\evil.dll", "hash"));
        assert!(p("c:\\windows", "eicar"));
        assert!(!p("c:\\windows\\temp\\x.exe", "dropper"), "Windows\\Temp may be cleaned");
        assert!(!p("c:\\windowsapps\\x.exe", "dropper"), "similar prefix is not the Windows folder");
        assert!(p("c:\\program files\\app\\a.exe", "dropper"), "heuristics never touch Program Files");
        assert!(!p("c:\\program files\\app\\a.exe", "hash"), "signature matches may");
        assert!(p("d:\\keepsafe\\a.exe", "hash"), "user protected dirs always win");
        assert!(!p("c:\\users\\me\\a.exe", "dropper"));
    }

    #[test]
    fn manual_items_are_never_changed() {
        let d = tmp("manual");
        let st = Store { dir: d.join("s") };
        fs::create_dir_all(&st.dir).unwrap();
        let t = Threat::new("task", "Heur:Task.Suspicious", "\\Evil".into(), "x.vbs".into(), Sev::Medium, Remedy::Manual);
        assert!(st.quarantine(&t).is_err() && st.destroy(&t).is_err());
        assert!(t.json().contains("\"manual\":true"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hosts_fix_removes_only_listed_lines() {
        let d = tmp("hosts");
        let h = d.join("hosts");
        fs::write(&h, "127.0.0.1 localhost\r\n0.0.0.0 www.kaspersky.com\r\n# keep\r\n10.0.0.1 mybox\r\n").unwrap();
        fix_hosts(h.to_str().unwrap(), &d, &["0.0.0.0 www.kaspersky.com".to_string()]).unwrap();
        let t = fs::read_to_string(&h).unwrap();
        assert!(t.contains("localhost") && t.contains("# keep") && t.contains("mybox") && !t.contains("kaspersky"));
        assert!(d.join("hosts.miniav.bak").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn persistence_judges() {
        assert!(judge_winlogon("Shell", "explorer.exe, evil.exe"));
        assert!(!judge_winlogon("Shell", "explorer.exe"));
        assert!(!judge_winlogon("Userinit", "C:\\Windows\\system32\\userinit.exe,"));
        assert!(judge_winlogon("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\x\\bad.exe"));
        assert!(!judge_winlogon("VMApplet", "anything"));
        let ifeo = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\r\n    Debugger    REG_SZ    C:\\x\\evil.exe\r\n\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\devenv.exe\r\n    Debugger    REG_SZ    vsjitdebugger.exe\r\n";
        let r = parse_ifeo(ifeo);
        assert_eq!(r.len(), 1);
        assert!(r[0].0.ends_with("taskmgr.exe\\Debugger") && r[0].1 == "C:\\x\\evil.exe");
        assert!(judge_exclusion("C:\\") && judge_exclusion("D:") && judge_exclusion("C:\\Users\\Me\\Downloads"));
        assert!(!judge_exclusion("C:\\Games\\MyGame"));
        let c = parse_csv_line("\"PC\",\"\\Evil Task\",\"N/A\",\"Ready\",\"x\",\"y\",\"0\",\"me\",\"wscript.exe \"\"C:\\a b\\x.vbs\"\"\",\"z\"");
        assert_eq!(c[1], "\\Evil Task");
        assert_eq!(c[8], "wscript.exe \"C:\\a b\\x.vbs\"");
        assert_eq!(parse_reg_values("    Shell    REG_SZ    explorer.exe\r\n").len(), 1);
    }
}
