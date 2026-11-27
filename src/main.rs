use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const INDEX_HTML: &str = include_str!("../web/index.html");
const MAX_JSON_BODY: usize = 512 * 1024; // 512 KB limit for JSON payloads
const MAX_OTA_BODY: usize = 15 * 1024 * 1024; // 15 MB limit for OTA binary

#[derive(Clone)]
struct Config {
    base_dir: PathBuf,
    log_path: PathBuf,
    pid_path: PathBuf,
    port: u16,
}

impl Config {
    fn from_env() -> Self {
        let default_base = if cfg!(target_os = "linux") {
            "/online/xray".to_string()
        } else {
            if Path::new("./dev_data").exists() {
                "./dev_data".to_string()
            } else if Path::new("../dev_data").exists() {
                "../dev_data".to_string()
            } else if Path::new("./b310-xray-panel/dev_data").exists() {
                "./b310-xray-panel/dev_data".to_string()
            } else {
                "./dev_data".to_string()
            }
        };
        let default_log = if cfg!(target_os = "linux") {
            "/tmp/xray.log".to_string()
        } else {
            format!("{}/xray.log", default_base)
        };
        let default_pid = if cfg!(target_os = "linux") {
            "/tmp/xray.pid".to_string()
        } else {
            format!("{}/xray.pid", default_base)
        };

        let base_dir = PathBuf::from(env::var("B310_DIR").unwrap_or_else(|_| default_base.into()));
        let log_path = PathBuf::from(env::var("B310_LOG").unwrap_or_else(|_| default_log.into()));
        let pid_path = PathBuf::from(env::var("B310_PID").unwrap_or_else(|_| default_pid.into()));
        let port = env::var("B310_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(5000);

        Self {
            base_dir,
            log_path,
            pid_path,
            port,
        }
    }

    fn profiles_path(&self) -> PathBuf {
        self.base_dir.join("profiles.json")
    }

    fn xray_config_path(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    fn xray_bin_path(&self) -> PathBuf {
        if cfg!(windows) {
            let primary = self.base_dir.join("xray.exe");
            if primary.exists() {
                return primary;
            }
            let candidates = [
                PathBuf::from("./dev_data/xray.exe"),
                PathBuf::from("../dev_data/xray.exe"),
                PathBuf::from("./b310-xray-panel/dev_data/xray.exe"),
                PathBuf::from("dev_data/xray.exe"),
                PathBuf::from("xray.exe"),
            ];
            for c in candidates {
                if c.exists() {
                    return c;
                }
            }
            if let Ok(exe) = env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let p = dir.join("xray.exe");
                    if p.exists() {
                        return p;
                    }
                    let p2 = dir.join("dev_data").join("xray.exe");
                    if p2.exists() {
                        return p2;
                    }
                    if let Some(parent) = dir.parent() {
                        let p3 = parent.join("dev_data").join("xray.exe");
                        if p3.exists() {
                            return p3;
                        }
                    }
                }
            }
            primary
        } else {
            self.base_dir.join("xray")
        }
    }

    fn net_script_path(&self) -> PathBuf {
        self.base_dir.join("net.sh")
    }

    fn auth_path(&self) -> PathBuf {
        self.base_dir.join("auth.json")
    }

    fn modem_settings_path(&self) -> PathBuf {
        self.base_dir.join("modem_settings.json")
    }
}

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

fn hash_secret(salt: &str, password: &str) -> String {
    let mut h = DefaultHasher::new();
    salt.hash(&mut h);
    password.hash(&mut h);
    let mut val = h.finish();
    for i in 0..1024u32 {
        let mut h2 = DefaultHasher::new();
        val.hash(&mut h2);
        i.hash(&mut h2);
        val = h2.finish();
    }
    format!("{:016x}", val)
}

fn generate_session_token() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let mut h = DefaultHasher::new();
    now.hash(&mut h);
    std::process::id().hash(&mut h);
    let mut val = h.finish();
    for i in 0..256u32 {
        let mut h2 = DefaultHasher::new();
        val.hash(&mut h2);
        i.hash(&mut h2);
        val = h2.finish();
    }
    format!("tk_{:016x}{:08x}", val, (now & 0xffffffff) as u32)
}

#[derive(Serialize, Deserialize, Clone)]
struct AuthConfig {
    salt: String,
    password_hash: String,
}

impl AuthConfig {
    fn default_config() -> Self {
        let salt = "sakura_b310_auth".to_string();
        let hash = hash_secret(&salt, "admin");
        Self {
            salt,
            password_hash: hash,
        }
    }

    fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = fs::read(path) {
                if let Ok(cfg) = serde_json::from_slice::<AuthConfig>(&data) {
                    return cfg;
                }
            }
        }
        let def = Self::default_config();
        let _ = def.save(path);
        def
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        write_atomic(path, &data)
    }

    fn verify(&self, input: &str) -> bool {
        let hash = hash_secret(&self.salt, input);
        self.password_hash == hash
    }

    fn update_password(&mut self, new_pass: &str, path: &Path) -> std::io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        self.salt = format!("s_{:x}", now);
        self.password_hash = hash_secret(&self.salt, new_pass);
        self.save(path)
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ProfilesStore {
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    profiles: Vec<Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ModemSettings {
    #[serde(default)]
    ttl_enabled: bool,
    #[serde(default = "default_ttl_val")]
    ttl_value: u32,
    #[serde(default)]
    cell_locked: bool,
    #[serde(default)]
    earfcn: String,
    #[serde(default)]
    pci: String,
}

fn default_ttl_val() -> u32 {
    64
}

impl Default for ModemSettings {
    fn default() -> Self {
        Self {
            ttl_enabled: false,
            ttl_value: 64,
            cell_locked: false,
            earfcn: String::new(),
            pci: String::new(),
        }
    }
}

impl ModemSettings {
    fn load(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = fs::read(path) {
                if let Ok(cfg) = serde_json::from_slice::<ModemSettings>(&data) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(path, json.as_bytes()).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct PowerRequest {
    action: String,
    #[serde(default)]
    config: Option<Value>,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    profile_name: Option<String>,
}

struct AppState {
    cfg: Config,
    started_at: Instant,
    xray_child: Option<Child>,
    adopted_pid: Option<u32>,
    vpn_desired: bool,
    server_ip: String,
    active_profile_name: String,
    watchdog_recoveries: u64,
    auth: AuthConfig,
    active_sessions: HashSet<String>,
}

impl AppState {
    fn new(cfg: Config) -> Self {
        let auth_path = cfg.auth_path();
        let auth = AuthConfig::load_or_default(&auth_path);
        let modem_cfg_path = cfg.modem_settings_path();
        let modem_settings = ModemSettings::load(&modem_cfg_path);
        if modem_settings.ttl_enabled {
            apply_ttl(true, modem_settings.ttl_value, &cfg.net_script_path());
        }
        if modem_settings.cell_locked && !modem_settings.earfcn.is_empty() {
            let _ = apply_cell_lock(true, &modem_settings.earfcn, &modem_settings.pci);
        }
        let mut state = Self {
            cfg,
            started_at: Instant::now(),
            xray_child: None,
            adopted_pid: None,
            vpn_desired: false,
            server_ip: String::new(),
            active_profile_name: String::new(),
            watchdog_recoveries: 0,
            auth,
            active_sessions: HashSet::new(),
        };
        state.adopt_existing_pid();
        state
    }

    /// Re-attach to an already-running Xray PID if the panel restarted (e.g. after OTA update).
    fn adopt_existing_pid(&mut self) {
        if let Ok(content) = fs::read_to_string(&self.cfg.pid_path) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if is_xray_pid_alive(pid) {
                    self.adopted_pid = Some(pid);
                    self.vpn_desired = true;
                } else {
                    let _ = fs::remove_file(&self.cfg.pid_path);
                }
            }
        }
    }

    /// Returns the PID if Xray is currently running, reaping exited child processes.
    fn current_pid(&mut self) -> Option<u32> {
        if let Some(child) = self.xray_child.as_mut() {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    self.xray_child = None;
                    let _ = fs::remove_file(&self.cfg.pid_path);
                    return None;
                }
                Ok(None) => return Some(child.id()),
                Err(_) => {
                    self.xray_child = None;
                    return None;
                }
            }
        }

        if let Some(pid) = self.adopted_pid {
            if is_xray_pid_alive(pid) {
                return Some(pid);
            }
            self.adopted_pid = None;
            let _ = fs::remove_file(&self.cfg.pid_path);
        }

        None
    }

    fn stop_xray(&mut self) {
        self.vpn_desired = false;
        if let Some(mut child) = self.xray_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(pid) = self.adopted_pid.take() {
            kill_pid(pid);
        }
        let _ = fs::remove_file(&self.cfg.pid_path);
        run_net_script(&self.cfg.net_script_path(), "stop", "");
    }
}

fn is_xray_pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(comm) = fs::read_to_string(comm_path) {
            return comm.trim().contains("xray");
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
}

fn kill_pid(pid: u32) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        thread::sleep(Duration::from_millis(150));
        if is_xray_pid_alive(pid) {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
    }
}

fn run_net_script(script_path: &Path, action: &str, server_ip: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("sh");
        cmd.arg(script_path).arg(action);
        if !server_ip.is_empty() {
            cmd.arg(server_ip);
        }
        match cmd.status() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (script_path, action, server_ip);
        true
    }
}

fn check_iptables_active(script_path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        if script_path.exists() {
            if let Ok(status) = Command::new("sh").arg(script_path).arg("status").output() {
                return status.status.success();
            }
        }
        Command::new("sh")
            .args(["-c", "iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q XRAY"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = script_path;
        true
    }
}

/// Resolves a server address or hostname into comma-separated IPv4 strings for iptables bypass.
fn resolve_server_ips(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Ok(IpAddr::V4(v4)) = trimmed.parse::<IpAddr>() {
        return v4.to_string();
    }

    // Attempt DNS resolution for hostname
    let target = format!("{}:443", trimmed);
    if let Ok(addrs) = target.to_socket_addrs() {
        let mut ips: Vec<String> = Vec::new();
        for addr in addrs {
            if let IpAddr::V4(v4) = addr.ip() {
                let s = v4.to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
                if ips.len() >= 4 {
                    break;
                }
            }
        }
        if !ips.is_empty() {
            return ips.join(",");
        }
    }

    String::new()
}

fn extract_address_from_config(cfg: &Value) -> String {
    if let Some(outbounds) = cfg.get("outbounds").and_then(|v| v.as_array()) {
        for ob in outbounds {
            if let Some(addr) = ob
                .pointer("/settings/vnext/0/address")
                .and_then(|v| v.as_str())
            {
                return addr.to_string();
            }
            if let Some(addr) = ob
                .pointer("/settings/servers/0/address")
                .and_then(|v| v.as_str())
            {
                return addr.to_string();
            }
        }
    }
    String::new()
}

fn start_xray_process(state: &mut AppState, config_val: Option<&Value>) -> Result<u32, String> {
    state.stop_xray();

    let cfg_path = state.cfg.xray_config_path();
    if let Some(val) = config_val {
        let formatted = serde_json::to_string_pretty(val)
            .map_err(|e| format!("Invalid config JSON: {}", e))?;
        write_atomic(&cfg_path, formatted.as_bytes())
            .map_err(|e| format!("Failed writing config.json: {}", e))?;
    } else if !cfg_path.exists() {
        return Err("Missing config.json payload".to_string());
    }

    let xray_bin = state.cfg.xray_bin_path();
    if !xray_bin.exists() {
        return Err(format!("Xray binary not found at {}", xray_bin.display()));
    }

    if let Some(parent) = state.cfg.log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&state.cfg.log_path)
        .map_err(|e| format!("Failed opening log file: {}", e))?;
    let log_err = log_file
        .try_clone()
        .map_err(|e| format!("Failed cloning log handle: {}", e))?;

    let mut cmd = Command::new(&xray_bin);
    cmd.args(["run", "-c"])
        .arg(&cfg_path)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err));

    #[cfg(target_os = "linux")]
    {
        cmd.env("GOGC", "20").env("GOMEMLIMIT", "24MiB");
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn xray: {}", e))?;

    // Brief startup check so immediate config/port errors surface to the UI
    thread::sleep(Duration::from_millis(250));
    match child.try_wait() {
        Ok(Some(status)) => {
            let tail = read_log_tail(&state.cfg.log_path, 15);
            return Err(format!("Xray exited immediately ({}):\n{}", status, tail));
        }
        Ok(None) => {}
        Err(e) => return Err(format!("Failed checking xray status: {}", e)),
    }

    let pid = child.id();
    let _ = fs::write(&state.cfg.pid_path, pid.to_string());
    state.xray_child = Some(child);
    state.vpn_desired = true;

    let net_ok = run_net_script(&state.cfg.net_script_path(), "start", &state.server_ip);
    if !net_ok {
        return Err("Xray started, but net.sh iptables setup failed".to_string());
    }

    Ok(pid)
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_meminfo() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let Ok(content) = fs::read_to_string("/proc/meminfo") else {
            return (0, 0);
        };
        let mut total = 0u64;
        let mut available = None;
        let mut free = 0u64;
        let mut buffers = 0u64;
        let mut cached = 0u64;

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap_or("");
            let val = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            match key {
                "MemTotal:" => total = val,
                "MemAvailable:" => available = Some(val),
                "MemFree:" => free = val,
                "Buffers:" => buffers = val,
                "Cached:" => cached = val,
                _ => {}
            }
        }

        // Kernel 3.4/3.10 on Huawei Balong lacks MemAvailable; estimate safely
        let avail = available.unwrap_or_else(|| free.saturating_add(buffers).saturating_add(cached));
        (total, avail)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (131072, 65536) // Dev fallback (128 MB total / 64 MB avail)
    }
}

fn read_system_uptime() -> u64 {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| {
                let first = s.split_whitespace().next()?;
                first.split('.').next()?.parse::<u64>().ok()
            })
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Parses `/proc/net/dev` and returns `(rx_bytes, tx_bytes)` prioritizing `wan0` (4G WAN).
fn parse_proc_net_dev(content: &str) -> (u64, u64) {
    let mut sum_rx = 0u64;
    let mut sum_tx = 0u64;
    for line in content.lines().skip(2) {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        let name = iface.trim();
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let rx = cols[0].parse::<u64>().unwrap_or(0);
        let tx = cols[8].parse::<u64>().unwrap_or(0);
        if name == "wan0" {
            return (rx, tx);
        }
        if name != "lo" && !name.starts_with("rmnet") && !name.starts_with("wl") && !name.starts_with("br") {
            sum_rx = sum_rx.saturating_add(rx);
            sum_tx = sum_tx.saturating_add(tx);
        }
    }
    (sum_rx, sum_tx)
}

#[cfg(target_os = "linux")]
fn read_net_bytes() -> (u64, u64) {
    fs::read_to_string("/proc/net/dev")
        .map(|c| parse_proc_net_dev(&c))
        .unwrap_or((0, 0))
}

#[cfg(windows)]
fn read_net_bytes() -> (u64, u64) {
    #[repr(C)]
    struct MibIfRow2 {
        interface_luid: u64,
        interface_index: u32,
        interface_guid: [u8; 16],
        alias: [u16; 257],
        description: [u16; 257],
        physical_address_length: u32,
        physical_address: [u8; 32],
        permanent_physical_address: [u8; 32],
        mtu: u32,
        if_type: u32,
        tunnel_type: u32,
        media_type: u32,
        physical_medium_type: u32,
        access_type: u32,
        direction_type: u32,
        flags: u8,
        oper_status: u32,
        admin_status: u32,
        media_connect_state: u32,
        network_guid: [u8; 16],
        connection_type: u32,
        transmit_link_speed: u64,
        receive_link_speed: u64,
        in_octets: u64,
        _in_rest: [u64; 8],
        out_octets: u64,
        _out_rest: [u64; 8],
    }

    #[repr(C)]
    struct MibIfTable2 {
        num_entries: u32,
        table: [MibIfRow2; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIfTable2(table: *mut *mut MibIfTable2) -> u32;
        fn FreeMibTable(memory: *mut std::ffi::c_void);
    }

    unsafe {
        let mut table_ptr: *mut MibIfTable2 = std::ptr::null_mut();
        if GetIfTable2(&mut table_ptr) != 0 || table_ptr.is_null() {
            return (0, 0);
        }
        let count = (*table_ptr).num_entries as usize;
        let rows = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), count);
        let mut rx = 0u64;
        let mut tx = 0u64;
        for row in rows {
            // Skip loopback (24), disconnected interfaces (oper_status != 1), and filter wrappers (flag bit 1)
            let is_hardware = (row.flags & 0x01) != 0;
            let is_filter = (row.flags & 0x02) != 0;
            if row.if_type != 24 && row.oper_status == 1 && is_hardware && !is_filter {
                rx = rx.saturating_add(row.in_octets);
                tx = tx.saturating_add(row.out_octets);
            }
        }
        FreeMibTable(table_ptr as *mut std::ffi::c_void);
        (rx, tx)
    }
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn read_net_bytes() -> (u64, u64) {
    (0, 0)
}

fn read_profiles_store(path: &Path) -> ProfilesStore {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<ProfilesStore>(&s).ok())
        .unwrap_or_default()
}

fn read_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return String::new();
    }

    const MAX_TAIL_BYTES: u64 = 16 * 1024;
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }

    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return String::new();
    }

    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(max_lines);
    lines[skip..].join("\n")
}

fn read_body_limited(request: &mut Request, max_bytes: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = request.body_length() {
        if len > max_bytes {
            return Err("Payload too large".to_string());
        }
    }
    let mut buf = Vec::new();
    let mut reader = request.as_reader().take((max_bytes + 1) as u64);
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read error: {}", e))?;
    if buf.len() > max_bytes {
        return Err("Payload exceeds maximum allowed size".to_string());
    }
    Ok(buf)
}

fn json_response(status: u16, body: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    Response::from_data(data)
        .with_status_code(StatusCode(status))
        .with_header(header)
}

fn html_response(html: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap();
    Response::from_data(html.as_bytes().to_vec())
        .with_status_code(StatusCode(200))
        .with_header(header)
}

fn handle_status(shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let (running, pid, panel_uptime, server_ip, mut active_name, recoveries, script_path, profiles_path) = {
        let mut st = shared.lock().unwrap();
        let pid = st.current_pid();
        (
            pid.is_some(),
            pid,
            st.started_at.elapsed().as_secs(),
            st.server_ip.clone(),
            st.active_profile_name.clone(),
            st.watchdog_recoveries,
            st.cfg.net_script_path(),
            st.cfg.profiles_path(),
        )
    };

    let (mem_total_kb, mem_available_kb) = read_meminfo();
    let system_uptime_secs = read_system_uptime();
    let (net_rx_bytes, net_tx_bytes) = read_net_bytes();
    let store = read_profiles_store(&profiles_path);

    if active_name.is_empty() {
        if let Some(ref aid) = store.active_id {
            for p in &store.profiles {
                if p.get("id").and_then(|v| v.as_str()) == Some(aid.as_str()) {
                    if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
                        active_name = name.to_string();
                    }
                    break;
                }
            }
        }
    }

    let iptables_ok = if running {
        check_iptables_active(&script_path)
    } else {
        false
    };

    json_response(
        200,
        json!({
            "running": running,
            "pid": pid,
            "panel_uptime_secs": panel_uptime,
            "system_uptime_secs": system_uptime_secs,
            "mem_total_kb": mem_total_kb,
            "mem_available_kb": mem_available_kb,
            "active_id": store.active_id,
            "active_profile_name": active_name,
            "server_ip": server_ip,
            "iptables_ok": iptables_ok,
            "watchdog_recoveries": recoveries,
            "net_rx_bytes": net_rx_bytes,
            "net_tx_bytes": net_tx_bytes,
            "platform": if cfg!(target_os = "linux") { "linux" } else { "windows" }
        }),
    )
}

fn handle_get_profiles(shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = {
        let st = shared.lock().unwrap();
        st.cfg.profiles_path()
    };
    let store = read_profiles_store(&path);
    json_response(200, json!(store))
}

fn handle_post_profiles(
    request: &mut Request,
    shared: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, MAX_JSON_BODY) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };

    let store: ProfilesStore = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => {
            return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)}))
        }
    };

    let formatted = match serde_json::to_vec_pretty(&store) {
        Ok(v) => v,
        Err(e) => return json_response(500, json!({"ok": false, "error": e.to_string()})),
    };

    let path = {
        let mut st = shared.lock().unwrap();
        if let Some(ref aid) = store.active_id {
            for p in &store.profiles {
                if p.get("id").and_then(|v| v.as_str()) == Some(aid.as_str()) {
                    st.active_profile_name = p
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    break;
                }
            }
        }
        st.cfg.profiles_path()
    };

    if let Err(e) = write_atomic(&path, &formatted) {
        return json_response(500, json!({"ok": false, "error": e.to_string()}));
    }

    json_response(200, json!({"ok": true}))
}

fn handle_power(
    request: &mut Request,
    shared: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, MAX_JSON_BODY) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };

    let req: PowerRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)}))
        }
    };

    let mut st = shared.lock().unwrap();
    match req.action.as_str() {
        "stop" => {
            st.stop_xray();
            json_response(200, json!({"ok": true, "running": false}))
        }
        "start" => {
            let raw_server = req
                .server_ip
                .filter(|s| !s.trim().is_empty())
                .or_else(|| req.config.as_ref().map(extract_address_from_config))
                .unwrap_or_default();
            st.server_ip = resolve_server_ips(&raw_server);
            if let Some(name) = req.profile_name {
                st.active_profile_name = name;
            }

            match start_xray_process(&mut st, req.config.as_ref()) {
                Ok(pid) => json_response(
                    200,
                    json!({
                        "ok": true,
                        "running": true,
                        "pid": pid,
                        "server_ip": st.server_ip
                    }),
                ),
                Err(err) => {
                    st.stop_xray();
                    json_response(500, json!({"ok": false, "running": false, "error": err}))
                }
            }
        }
        other => json_response(
            400,
            json!({"ok": false, "error": format!("Unknown action: {}", other)}),
        ),
    }
}

fn handle_logs(
    method: &Method,
    shared: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let log_path = {
        let st = shared.lock().unwrap();
        st.cfg.log_path.clone()
    };

    if *method == Method::Delete || *method == Method::Post {
        let _ = fs::write(&log_path, "");
        return json_response(200, json!({"ok": true, "logs": ""}));
    }

    let logs = read_log_tail(&log_path, 50);
    let size_bytes = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    json_response(200, json!({"logs": logs, "size_bytes": size_bytes}))
}

fn handle_ota_update(
    request: &mut Request,
    shared: &Arc<Mutex<AppState>>,
) -> (Response<std::io::Cursor<Vec<u8>>>, bool) {
    if let Some(len) = request.body_length() {
        if len == 0 || len > MAX_OTA_BODY {
            return (
                json_response(400, json!({"ok": false, "error": "Invalid binary size"})),
                false,
            );
        }
    }

    let target_path = if cfg!(target_os = "linux") {
        env::current_exe().unwrap_or_else(|_| PathBuf::from("/online/xray/b310-xray-panel"))
    } else {
        let st = shared.lock().unwrap();
        st.cfg.base_dir.join("b310-xray-panel")
    };

    let tmp_path = target_path.with_extension("new");

    if let Some(parent) = tmp_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut out = match File::create(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            return (
                json_response(500, json!({"ok": false, "error": e.to_string()})),
                false,
            )
        }
    };

    let mut reader = request.as_reader().take((MAX_OTA_BODY + 1) as u64);
    let mut buf = [0u8; 8192];
    let mut total: usize = 0;
    let mut header_bytes = [0u8; 4];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if total == 0 && n >= 4 {
                    header_bytes.copy_from_slice(&buf[..4]);
                }
                total += n;
                if total > MAX_OTA_BODY {
                    let _ = fs::remove_file(&tmp_path);
                    return (
                        json_response(400, json!({"ok": false, "error": "Binary exceeds 15 MB limit"})),
                        false,
                    );
                }
                if let Err(e) = out.write_all(&buf[..n]) {
                    let _ = fs::remove_file(&tmp_path);
                    return (
                        json_response(500, json!({"ok": false, "error": e.to_string()})),
                        false,
                    );
                }
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                return (
                    json_response(400, json!({"ok": false, "error": e.to_string()})),
                    false,
                );
            }
        }
    }

    if total < 1024 {
        let _ = fs::remove_file(&tmp_path);
        return (
            json_response(400, json!({"ok": false, "error": "Uploaded file too small"})),
            false,
        );
    }

    #[cfg(target_os = "linux")]
    if &header_bytes != b"\x7fELF" {
        let _ = fs::remove_file(&tmp_path);
        return (
            json_response(
                400,
                json!({"ok": false, "error": "Invalid binary: missing ELF header"}),
            ),
            false,
        );
    }

    drop(out);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Err(e) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755)) {
            let _ = fs::remove_file(&tmp_path);
            return (
                json_response(500, json!({"ok": false, "error": format!("chmod failed: {}", e)})),
                false,
            );
        }

        // Stop Xray cleanly so the restarted panel starts from a clean state
        {
            let mut st = shared.lock().unwrap();
            st.stop_xray();
        }

        if let Err(e) = fs::rename(&tmp_path, &target_path) {
            let _ = fs::remove_file(&tmp_path);
            return (
                json_response(500, json!({"ok": false, "error": format!("Failed replacing binary: {}", e)})),
                false,
            );
        }

        return (
            json_response(
                200,
                json!({"ok": true, "bytes": total, "message": "OTA update applied. Restarting..."}),
            ),
            true,
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = header_bytes;
        (
            json_response(
                200,
                json!({
                    "ok": true,
                    "bytes": total,
                    "message": "OTA dry-run saved (non-Linux dev mode, not exiting)"
                }),
            ),
            false,
        )
    }
}

fn spawn_watchdog(shared: Arc<Mutex<AppState>>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));

        let mut st = shared.lock().unwrap();
        if !st.vpn_desired {
            continue;
        }

        // Check if Xray crashed unexpectedly while VPN was supposed to be active
        if st.current_pid().is_none() {
            let cfg_path = st.cfg.xray_config_path();
            if cfg_path.exists() {
                if start_xray_process(&mut st, None).is_ok() {
                    st.watchdog_recoveries += 1;
                } else {
                    st.vpn_desired = false;
                    run_net_script(&st.cfg.net_script_path(), "stop", "");
                }
            }
            continue;
        }

        // Verify iptables PREROUTING rules remain intact (Huawei 4G reconnects can reset NAT)
        let script = st.cfg.net_script_path();
        if !check_iptables_active(&script) {
            let ip = st.server_ip.clone();
            if run_net_script(&script, "start", &ip) {
                st.watchdog_recoveries += 1;
            }
        }
        let m_settings = ModemSettings::load(&st.cfg.modem_settings_path());
        if m_settings.ttl_enabled {
            apply_ttl(true, m_settings.ttl_value, &script);
        }
    });
}

fn handle_modem_signal() -> Response<std::io::Cursor<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(resp) = query_hilink_api("/api/device/signal") {
            if let Some(data) = parse_hilink_signal(&resp) {
                return json_response(200, data);
            }
        }
    }

    let is_win = cfg!(windows);
    json_response(200, json!({
        "ok": true,
        "platform": if is_win { "windows" } else { "linux" },
        "has_modem": false,
        "operator": if is_win { "Mode Simulasi PC (Tanpa Modem LTE)" } else { "Modem HiLink Tidak Terdeteksi" },
        "network_type": if is_win { "PC Local Dev" } else { "Offline" },
        "band": "--",
        "band_id": "--",
        "rsrp": null,
        "rsrq": null,
        "rssi": null,
        "sinr": null,
        "cell_id": "--",
        "pci": "--",
        "earfcn": if is_win { "1800" } else { "--" },
        "bars": 0,
        "bandwidth": "--",
        "is_mock": is_win,
        "message": if is_win {
            "Berjalan di Windows tanpa modem Balong HiLink. Parameter sinyal nyata hanya aktif di router Huawei B310s."
        } else {
            "Layanan HiLink di 127.0.0.1:80 tidak merespon."
        }
    }))
}

fn handle_modem_band(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };
    let band = body.get("band").and_then(|v| v.as_str()).unwrap_or("AUTO");

    #[cfg(target_os = "linux")]
    {
        let lte_band_hex = match band {
            "B1" => "1",
            "B3" => "4",
            "B8" => "80",
            "B40" => "8000000000",
            "B1+B3" => "5",
            _ => "7FFFFFFFFFFFFFFF",
        };
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><NetworkMode>03</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>{}</LTEBand></request>",
            lte_band_hex
        );
        let _ = post_hilink_api("/api/net/net-mode", &xml);
    }

    let is_win = cfg!(windows);
    let msg = if is_win {
        format!("[Simulasi PC] Frekuensi band {} dipilih (pada router B310s dikirim ke modem HiLink /api/net/net-mode).", band)
    } else {
        format!("Band berhasil dikunci ke {}", band)
    };

    json_response(200, json!({
        "ok": true,
        "message": msg,
        "band": band
    }))
}

fn handle_modem_change_ip() -> Response<std::io::Cursor<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        let off_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><dataswitch>0</dataswitch></request>";
        let on_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><dataswitch>1</dataswitch></request>";
        let _ = post_hilink_api("/api/dialup/mobile-dataswitch", off_xml);
        thread::sleep(Duration::from_millis(1500));
        let _ = post_hilink_api("/api/dialup/mobile-dataswitch", on_xml);
    }

    let msg = if cfg!(windows) {
        "[Simulasi PC] Sinyal ganti IP diterima. Pada router B310s data seluler akan di-restart otomatis via HiLink."
    } else {
        "Data seluler di-restart. IP operator baru sedang dinegosiasikan."
    };

    json_response(200, json!({
        "ok": true,
        "message": msg
    }))
}

fn handle_modem_reboot() -> Response<std::io::Cursor<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        thread::spawn(|| {
            thread::sleep(Duration::from_millis(800));
            let _ = Command::new("reboot").output();
            let reboot_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Control>1</Control></request>";
            let _ = post_hilink_api("/api/device/control", reboot_xml);
        });
    }

    json_response(200, json!({
        "ok": true,
        "message": "Router sedang melakukan restart ulang..."
    }))
}

fn handle_modem_ussd(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("*888#");

    #[cfg(target_os = "linux")]
    {
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><content>{}</content><codeType>CodeType</codeType></request>",
            code
        );
        if let Ok(_) = post_hilink_api("/api/ussd/send", &xml) {
            thread::sleep(Duration::from_millis(1200));
            if let Ok(status) = query_hilink_api("/api/ussd/get") {
                if let Some(msg) = extract_xml_tag(&status, "content") {
                    return json_response(200, json!({"ok": true, "response": msg}));
                }
            }
        }
    }

    let is_win = cfg!(windows);
    let msg = if is_win {
        format!("[Simulasi PC] Panggilan USSD '{}' dikirim. Balasan nyata akan membaca kartu SIM melalui Balong HiLink saat berjalan di router B310s.", code)
    } else {
        format!("Gagal menghubungi modem HiLink untuk USSD {}. Pastikan SIM card terpasang dan modem aktif.", code)
    };

    json_response(200, json!({
        "ok": true,
        "code": code,
        "is_mock": is_win,
        "response": msg
    }))
}

fn apply_ttl(enabled: bool, value: u32, script_path: &Path) {
    #[cfg(target_os = "linux")]
    {
        if enabled {
            let val_str = value.to_string();
            let _ = Command::new("sh")
                .arg(script_path)
                .arg("ttl_set")
                .arg(&val_str)
                .output();
            let _ = Command::new("sysctl")
                .arg("-w")
                .arg(format!("net.ipv4.ip_default_ttl={}", value))
                .output();
        } else {
            let _ = Command::new("sh")
                .arg(script_path)
                .arg("ttl_unset")
                .output();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (enabled, value, script_path);
    }
}

fn apply_cell_lock(lock: bool, earfcn: &str, pci: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        let cmd = if lock {
            if !pci.is_empty() {
                format!("AT^FREQLOCK=1,\"03\",{},{}\r\n", earfcn, pci)
            } else {
                format!("AT^FREQLOCK=1,{}\r\n", earfcn)
            }
        } else {
            "AT^FREQLOCK=0\r\n".to_string()
        };

        let candidates = ["/dev/appvcom1", "/dev/appvcom", "/dev/ttyUSB0", "/dev/ttyUSB1"];
        let mut sent = false;
        for dev in &candidates {
            if let Ok(mut file) = fs::OpenOptions::new().write(true).open(dev) {
                if file.write_all(cmd.as_bytes()).is_ok() {
                    sent = true;
                    break;
                }
            }
        }

        if sent {
            Ok(if lock {
                format!("Perintah Cell Lock (EARFCN: {}, PCI: {}) berhasil dikirim ke modem Balong.", earfcn, pci)
            } else {
                "Perintah pelepasan Cell Lock (AT^FREQLOCK=0) berhasil dikirim ke modem Balong.".to_string()
            })
        } else {
            Ok(if lock {
                format!("Konfigurasi Cell Lock tersimpan (EARFCN: {}, PCI: {}). Port AT serial (/dev/appvcom) akan merespon pada router fisik.", earfcn, pci)
            } else {
                "Cell Lock dinonaktifkan.".to_string()
            })
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (lock, earfcn, pci);
        Ok(if lock {
            format!("[Simulasi PC] Cell Lock diaktifkan untuk EARFCN: {}, PCI: {}. Pada router B310s akan dikirim perintah AT^FREQLOCK.", earfcn, pci)
        } else {
            "[Simulasi PC] Cell Lock dinonaktifkan (AT^FREQLOCK=0).".to_string()
        })
    }
}

fn handle_get_ttl(shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let st = shared.lock().unwrap();
    let settings = ModemSettings::load(&st.cfg.modem_settings_path());
    json_response(200, json!({
        "ok": true,
        "enabled": settings.ttl_enabled,
        "value": settings.ttl_value
    }))
}

fn handle_set_ttl(shared: &Arc<Mutex<AppState>>, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };

    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let value = body.get("value").and_then(|v| v.as_u64()).unwrap_or(64) as u32;

    let (script_path, settings_path) = {
        let st = shared.lock().unwrap();
        (st.cfg.net_script_path(), st.cfg.modem_settings_path())
    };

    apply_ttl(enabled, value, &script_path);

    let mut settings = ModemSettings::load(&settings_path);
    settings.ttl_enabled = enabled;
    settings.ttl_value = value;
    let _ = settings.save(&settings_path);

    let msg = if enabled {
        format!("Bypass Tethering TTL {} berhasil diaktifkan. Seluruh perangkat yang terhubung akan memakai kuota reguler.", value)
    } else {
        "Bypass Tethering TTL dinonaktifkan (kembali ke TTL default sistem).".to_string()
    };

    json_response(200, json!({
        "ok": true,
        "enabled": enabled,
        "value": value,
        "message": msg
    }))
}

fn handle_get_cell_lock(shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let st = shared.lock().unwrap();
    let settings = ModemSettings::load(&st.cfg.modem_settings_path());
    json_response(200, json!({
        "ok": true,
        "locked": settings.cell_locked,
        "earfcn": settings.earfcn,
        "pci": settings.pci
    }))
}

fn handle_set_cell_lock(shared: &Arc<Mutex<AppState>>, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };

    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("lock");
    let earfcn = body.get("earfcn").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let pci = body.get("pci").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

    let settings_path = {
        let st = shared.lock().unwrap();
        st.cfg.modem_settings_path()
    };

    let mut settings = ModemSettings::load(&settings_path);

    if action == "unlock" {
        let _ = apply_cell_lock(false, "", "");
        settings.cell_locked = false;
        let _ = settings.save(&settings_path);
        return json_response(200, json!({
            "ok": true,
            "locked": false,
            "message": "Kunci pemancar (Cell Lock) berhasil dilepas. Modem kembali ke pemilihan menara otomatis."
        }));
    }

    if earfcn.is_empty() {
        return json_response(400, json!({
            "ok": false,
            "error": "Nomor EARFCN tidak boleh kosong untuk melakukan Cell Lock."
        }));
    }

    let msg = match apply_cell_lock(true, &earfcn, &pci) {
        Ok(m) => m,
        Err(e) => format!("Peringatan: {}", e),
    };

    settings.cell_locked = true;
    settings.earfcn = earfcn.clone();
    settings.pci = pci.clone();
    let _ = settings.save(&settings_path);

    json_response(200, json!({
        "ok": true,
        "locked": true,
        "earfcn": earfcn,
        "pci": pci,
        "message": msg
    }))
}

#[cfg(target_os = "linux")]
fn query_hilink_api(path: &str) -> std::io::Result<String> {
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect("127.0.0.1:80")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path);
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    Ok(resp)
}

#[cfg(target_os = "linux")]
fn post_hilink_api(path: &str, body: &str) -> std::io::Result<String> {
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect("127.0.0.1:80")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    Ok(resp)
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].trim().to_string())
}

#[cfg(target_os = "linux")]
fn get_hilink_operator() -> String {
    if let Ok(resp) = query_hilink_api("/api/net/current-plmn") {
        if let Some(name) = extract_xml_tag(&resp, "FullName") {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
        if let Some(short) = extract_xml_tag(&resp, "ShortName") {
            if !short.trim().is_empty() {
                return short.trim().to_string();
            }
        }
    }
    "4G LTE".to_string()
}

#[cfg(target_os = "linux")]
fn parse_hilink_signal(xml: &str) -> Option<Value> {
    let pci = extract_xml_tag(xml, "pci").unwrap_or_else(|| "-".into());
    let cell_id = extract_xml_tag(xml, "cell_id").unwrap_or_else(|| "-".into());
    let band_num = extract_xml_tag(xml, "band").unwrap_or_else(|| "3".into());
    let rsrq = extract_xml_tag(xml, "rsrq").unwrap_or_else(|| "-8dB".into());
    let rsrp = extract_xml_tag(xml, "rsrp").unwrap_or_else(|| "-85dBm".into());
    let rssi = extract_xml_tag(xml, "rssi").unwrap_or_else(|| "-61dBm".into());
    let sinr = extract_xml_tag(xml, "sinr").unwrap_or_else(|| "15dB".into());
    let bw = extract_xml_tag(xml, "dlbandwidth").unwrap_or_else(|| "20MHz".into());
    let earfcn = extract_xml_tag(xml, "earfcn")
        .or_else(|| extract_xml_tag(xml, "dlfrequency"))
        .unwrap_or_else(|| match band_num.as_str() {
            "1" => "100".into(),
            "3" => "1800".into(),
            "8" => "3700".into(),
            "40" => "39150".into(),
            _ => "1800".into(),
        });

    let rsrp_num = rsrp.trim_end_matches("dBm").trim().parse::<i32>().unwrap_or(-85);
    let bars = if rsrp_num >= -80 { 5 } else if rsrp_num >= -90 { 4 } else if rsrp_num >= -100 { 3 } else if rsrp_num >= -110 { 2 } else { 1 };

    let op = get_hilink_operator();

    Some(json!({
        "ok": true,
        "platform": "linux",
        "has_modem": true,
        "operator": op,
        "network_type": "LTE (4G)",
        "band": format!("Band {} ({} MHz)", band_num, match band_num.as_str() { "1" => "2100", "8" => "900", "40" => "2300", _ => "1800" }),
        "band_id": format!("B{}", band_num),
        "rsrp": rsrp_num,
        "rsrq": rsrq.trim_end_matches("dB").trim().parse::<i32>().unwrap_or(-8),
        "rssi": rssi.trim_end_matches("dBm").trim().parse::<i32>().unwrap_or(-61),
        "sinr": sinr.trim_end_matches("dB").trim().parse::<i32>().unwrap_or(15),
        "cell_id": cell_id,
        "pci": pci,
        "earfcn": earfcn,
        "bars": bars,
        "bandwidth": bw,
        "is_mock": false
    }))
}

fn extract_auth_token(req: &Request) -> Option<String> {
    for h in req.headers() {
        let name = h.field.as_str().as_str();
        if name.eq_ignore_ascii_case("X-Auth-Token") {
            let val = h.value.as_str().trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
        if name.eq_ignore_ascii_case("Authorization") {
            let val = h.value.as_str().trim();
            if val.to_ascii_lowercase().starts_with("bearer ") {
                let token = val[7..].trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
        if name.eq_ignore_ascii_case("Cookie") {
            let val = h.value.as_str();
            for part in val.split(';') {
                let p = part.trim();
                if p.starts_with("xray_token=") {
                    let token = p["xray_token=".len()..].trim();
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }
    None
}

fn handle_auth_check(req: &Request, shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let token = extract_auth_token(req);
    let st = shared.lock().unwrap();
    let is_authed = match token {
        Some(t) => st.active_sessions.contains(&t),
        None => false,
    };
    json_response(200, json!({
        "ok": true,
        "authenticated": is_authed
    }))
}

fn handle_auth_login(req: &mut Request, shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };
    let pass = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let mut st = shared.lock().unwrap();
    if st.auth.verify(pass) {
        let token = generate_session_token();
        st.active_sessions.insert(token.clone());
        let cookie_val = format!("xray_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000", token);
        let header = Header::from_bytes("Set-Cookie", cookie_val.as_bytes()).unwrap();
        let data = serde_json::to_vec(&json!({
            "ok": true,
            "token": token,
            "message": "Login berhasil!"
        })).unwrap();
        let h_type = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
        Response::from_data(data)
            .with_status_code(StatusCode(200))
            .with_header(h_type)
            .with_header(header)
    } else {
        json_response(401, json!({
            "ok": false,
            "error": "Password salah! (Bawaan awal: admin)"
        }))
    }
}

fn handle_auth_logout(req: &Request, shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    if let Some(t) = extract_auth_token(req) {
        let mut st = shared.lock().unwrap();
        st.active_sessions.remove(&t);
    }
    let h_type = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let h_cookie = Header::from_bytes("Set-Cookie", "xray_token=; Path=/; HttpOnly; Max-Age=0").unwrap();
    let data = serde_json::to_vec(&json!({"ok": true, "message": "Logout berhasil"})).unwrap();
    Response::from_data(data)
        .with_status_code(StatusCode(200))
        .with_header(h_type)
        .with_header(h_cookie)
}

fn handle_auth_password(req: &mut Request, shared: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let raw = match read_body_limited(req, 16 * 1024) {
        Ok(b) => b,
        Err(e) => return json_response(400, json!({"ok": false, "error": e})),
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return json_response(400, json!({"ok": false, "error": format!("Invalid JSON: {}", e)})),
    };
    let old_pw = body.get("old_password").and_then(|v| v.as_str()).unwrap_or("");
    let new_pw = body.get("new_password").and_then(|v| v.as_str()).unwrap_or("");

    if new_pw.trim().len() < 4 {
        return json_response(400, json!({"ok": false, "error": "Password baru minimal 4 karakter!"}));
    }

    let mut st = shared.lock().unwrap();
    if !st.auth.verify(old_pw) {
        return json_response(401, json!({"ok": false, "error": "Password lama salah!"}));
    }

    let path = st.cfg.auth_path();
    if let Err(e) = st.auth.update_password(new_pw.trim(), &path) {
        return json_response(500, json!({"ok": false, "error": format!("Gagal menyimpan password: {}", e)}));
    }

    json_response(200, json!({
        "ok": true,
        "message": "Password berhasil diubah!"
    }))
}

fn main() {
    let cfg = Config::from_env();
    let _ = fs::create_dir_all(&cfg.base_dir);

    let bind_addr = format!("0.0.0.0:{}", cfg.port);
    let server = Server::http(&bind_addr).unwrap_or_else(|e| {
        eprintln!("Failed to bind {}: {}", bind_addr, e);
        std::process::exit(1);
    });

    println!(
        "Erlkim Xray Panel listening on http://127.0.0.1:{} (bound {}, dir: {})",
        cfg.port,
        bind_addr,
        cfg.base_dir.display()
    );

    let shared = Arc::new(Mutex::new(AppState::new(cfg)));
    spawn_watchdog(Arc::clone(&shared));

    for mut request in server.incoming_requests() {
        let url_path = request.url().split('?').next().unwrap_or("/");
        let method = request.method().clone();
        let mut should_exit_for_ota = false;

        let is_public = matches!(
            (method.clone(), url_path),
            (Method::Get, "/")
                | (Method::Get, "/index.html")
                | (Method::Get, "/favicon.ico")
                | (Method::Get, "/api/ping")
                | (Method::Get, "/api/auth/check")
                | (Method::Post, "/api/auth/login")
        );

        if !is_public && url_path.starts_with("/api/") {
            let token = extract_auth_token(&request);
            let authed = match token {
                Some(t) => {
                    let st = shared.lock().unwrap();
                    st.active_sessions.contains(&t)
                }
                None => false,
            };
            if !authed {
                let resp = json_response(401, json!({
                    "ok": false,
                    "error": "Sesi belum terautentikasi atau telah berakhir",
                    "auth_required": true
                }));
                let _ = request.respond(resp);
                continue;
            }
        }

        let response = match (method, url_path) {
            (Method::Get, "/") | (Method::Get, "/index.html") => html_response(INDEX_HTML),
            (Method::Get, "/favicon.ico") => json_response(404, json!({})),
            (Method::Get, "/api/ping") => json_response(200, json!({"ok": true})),
            (Method::Get, "/api/auth/check") => handle_auth_check(&request, &shared),
            (Method::Post, "/api/auth/login") => handle_auth_login(&mut request, &shared),
            (Method::Post, "/api/auth/logout") => handle_auth_logout(&request, &shared),
            (Method::Post, "/api/auth/password") => handle_auth_password(&mut request, &shared),
            (Method::Get, "/api/status") => handle_status(&shared),
            (Method::Get, "/api/profiles") => handle_get_profiles(&shared),
            (Method::Post, "/api/profiles") => handle_post_profiles(&mut request, &shared),
            (Method::Post, "/api/power") => handle_power(&mut request, &shared),
            (m @ Method::Get, "/api/logs")
            | (m @ Method::Post, "/api/logs")
            | (m @ Method::Delete, "/api/logs") => handle_logs(&m, &shared),
            (Method::Post, "/api/update") => {
                let (resp, restart) = handle_ota_update(&mut request, &shared);
                should_exit_for_ota = restart;
                resp
            }
            (Method::Get, "/api/modem/signal") => handle_modem_signal(),
            (Method::Post, "/api/modem/band") => handle_modem_band(&mut request),
            (Method::Post, "/api/modem/change-ip") => handle_modem_change_ip(),
            (Method::Post, "/api/modem/reboot") => handle_modem_reboot(),
            (Method::Post, "/api/modem/ussd") => handle_modem_ussd(&mut request),
            (Method::Get, "/api/modem/ttl") => handle_get_ttl(&shared),
            (Method::Post, "/api/modem/ttl") => handle_set_ttl(&shared, &mut request),
            (Method::Get, "/api/modem/cell-lock") => handle_get_cell_lock(&shared),
            (Method::Post, "/api/modem/cell-lock") => handle_set_cell_lock(&shared, &mut request),
            _ => json_response(404, json!({"error": "Not found"})),
        };

        let _ = request.respond(response);

        if should_exit_for_ota {
            thread::sleep(Duration::from_millis(300));
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_dev_prefers_wan0() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   169503     730    0    0    0     0          0         0   169503     730    0    0    0     0       0          0
  eth0: 35790706   42889    0    0    0     0          0         0  7281219   33312    0    0    0     0       0          0
  wan0:  1048576     500    0    0    0     0          0         0   524288     250    0    0    0     0       0          0
";
        assert_eq!(parse_proc_net_dev(sample), (1048576, 524288));
    }

    #[test]
    fn test_read_net_bytes_runs() {
        let (rx, tx) = read_net_bytes();
        // On active Windows/Linux host, function should succeed without panicking
        let _ = (rx, tx);
    }
}
