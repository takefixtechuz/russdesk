// Fixtech (27.10.2026): инвентаризация устройства для кабинета Fixtech Remote.
// Раз в INTERVAL (и при старте) клиент собирает железо/ОС/сеть/безопасность и шлёт JSON
// на INVENTORY_URL. Кабинет сверяет id+uuid с сервером sctgdesk, отдельного секрета нет.
// Всё best-effort: любая команда может не сработать — тогда поле просто пустое.

use hbb_common::{config::Config, log};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const INVENTORY_URL: &str = "https://remote.fixtech.uz/api/inventory";
const INTERVAL: Duration = Duration::from_secs(6 * 3600);
const RETRY: Duration = Duration::from_secs(10 * 60);

lazy_static::lazy_static! {
    static ref NEXT: Mutex<Option<Instant>> = Mutex::new(None);
}

/// Вызывается из heartbeat-цикла (каждые 15 с); реально работает раз в INTERVAL.
pub async fn tick() {
    let due = NEXT.lock().unwrap().map(|t| Instant::now() >= t).unwrap_or(true);
    if !due {
        return;
    }
    *NEXT.lock().unwrap() = Some(Instant::now() + INTERVAL);
    let v = match tokio::task::spawn_blocking(collect).await {
        Ok(v) => v,
        Err(e) => {
            log::warn!("inventory collect failed: {}", e);
            return;
        }
    };
    match crate::post_request(INVENTORY_URL.to_owned(), v.to_string(), "").await {
        Ok(r) => log::info!("inventory uploaded: {}", r.chars().take(100).collect::<String>()),
        Err(e) => {
            log::warn!("inventory upload failed: {}", e);
            *NEXT.lock().unwrap() = Some(Instant::now() + RETRY);
        }
    }
}

fn run(cmd: &str, args: &[&str]) -> String {
    let mut c = Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match c.output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(windows)]
fn ps(script: &str) -> String {
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    )
}

#[cfg(target_os = "android")]
fn getprop(name: &str) -> String {
    run("getprop", &[name])
}

fn lines(s: String) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn collect() -> Value {
    let mut v = crate::get_sysinfo();
    v["id"] = json!(Config::get_id());
    v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
    v["version"] = json!(crate::VERSION);
    v["platform"] = json!(std::env::consts::OS);
    v["arch"] = json!(std::env::consts::ARCH);
    v["collected_at"] = json!(hbb_common::get_time() / 1000);
    v["displays"] = displays();
    v["gpu"] = json!(gpu());
    v["storage"] = json!(storage());
    v["nics"] = nics();
    v["security"] = security();
    v
}

// ---- экраны --------------------------------------------------------------------

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn displays() -> Value {
    match scrap::Display::all() {
        Ok(ds) => json!(ds
            .iter()
            .map(|d| json!({
                "name": d.name(),
                "width": d.width() as i64,
                "height": d.height() as i64,
                "primary": d.is_primary(),
            }))
            .collect::<Vec<_>>()),
        Err(e) => json!([{ "error": e.to_string() }]),
    }
}

#[cfg(target_os = "android")]
fn displays() -> Value {
    // MainService отдаёт размер захвата и масштаб; физическое разрешение = размер × масштаб.
    let s = scrap::android::call_main_service_get_by_name("screen_size").unwrap_or_default();
    match serde_json::from_str::<Value>(&s) {
        Ok(j) => {
            let w = j["width"].as_i64().unwrap_or(0);
            let h = j["height"].as_i64().unwrap_or(0);
            let scale = j["scale"].as_i64().unwrap_or(1).max(1);
            json!([{ "name": "screen", "width": w * scale, "height": h * scale, "primary": true }])
        }
        Err(_) => json!([]),
    }
}

#[cfg(target_os = "ios")]
fn displays() -> Value {
    json!([])
}

// ---- видеокарта -------------------------------------------------------------------

fn gpu() -> Vec<String> {
    #[cfg(windows)]
    {
        return lines(ps(
            "Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name + ' (' + [math]::Round($_.AdapterRAM/1MB) + ' MB, драйвер ' + $_.DriverVersion + ')' }",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        return lines(run(
            "sh",
            &["-c", "lspci 2>/dev/null | grep -iE 'vga|3d|display' | cut -d: -f3- | sed 's/^ *//'"],
        ));
    }
    #[cfg(target_os = "macos")]
    {
        return lines(run(
            "sh",
            &["-c", "system_profiler SPDisplaysDataType 2>/dev/null | grep -E 'Chipset Model' | cut -d: -f2 | sed 's/^ *//'"],
        ));
    }
    #[cfg(target_os = "android")]
    {
        let egl = getprop("ro.hardware.egl");
        let platform = getprop("ro.board.platform");
        let hw = getprop("ro.hardware");
        let mut s = String::new();
        if !egl.is_empty() {
            s.push_str(&egl);
        }
        if !platform.is_empty() {
            s.push_str(&format!(" (платформа {})", platform));
        } else if !hw.is_empty() {
            s.push_str(&format!(" ({})", hw));
        }
        return if s.is_empty() { vec![] } else { vec![s.trim().to_string()] };
    }
    #[allow(unreachable_code)]
    vec![]
}

// ---- накопители ------------------------------------------------------------------

fn storage() -> Vec<String> {
    #[cfg(windows)]
    {
        return lines(ps(
            "Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object { $_.Name + ': занято ' + [math]::Round($_.Used/1GB) + ' из ' + [math]::Round(($_.Used+$_.Free)/1GB) + ' GB' }",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return lines(run(
            "sh",
            &["-c", "df -hP / /home 2>/dev/null | tail -n +2 | awk '{print $6\": занято \"$3\" из \"$2\" (\"$5\")\"}' | sort -u"],
        ));
    }
    #[cfg(target_os = "android")]
    {
        return lines(run(
            "sh",
            &["-c", "df -h /data 2>/dev/null | tail -n +2 | awk '{print \"/data: занято \"$3\" из \"$2\" (\"$5\")\"}'"],
        ));
    }
    #[allow(unreachable_code)]
    vec![]
}

// ---- сеть -----------------------------------------------------------------------

#[cfg(not(target_os = "ios"))]
fn nics() -> Value {
    let mut out = Vec::new();
    for i in default_net::get_interfaces() {
        let ipv4: Vec<String> = i.ipv4.iter().map(|n| format!("{}/{}", n.addr, n.prefix_len)).collect();
        let ipv6: Vec<String> = i.ipv6.iter().map(|n| n.addr.to_string()).collect();
        let mac = i.mac_addr.map(|m| m.address()).unwrap_or_default();
        let loopback = ipv4.iter().all(|a| a.starts_with("127.")) && ipv6.iter().all(|a| a == "::1");
        if (ipv4.is_empty() && mac.is_empty()) || (loopback && !ipv4.is_empty()) {
            continue;
        }
        out.push(json!({
            "name": i.friendly_name.clone().unwrap_or(i.name.clone()),
            "type": format!("{:?}", i.if_type),
            "mac": mac,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gateway": i.gateway.as_ref().map(|g| g.ip_addr.to_string()),
            "speed_mbps": i.transmit_speed.map(|s| s / 1_000_000),
        }));
    }
    json!(out)
}

#[cfg(target_os = "ios")]
fn nics() -> Value {
    json!([])
}

// ---- безопасность -----------------------------------------------------------------

#[cfg(windows)]
fn security() -> Value {
    // Один вызов PowerShell → JSON. Каждое поле в try, чтобы без прав админа отдать хотя бы остальное.
    let script = r#"
$r = [ordered]@{}
try { $r.secure_boot = [bool](Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' UEFISecureBootEnabled) } catch { $r.secure_boot = $null }
try { $t = Get-Tpm; $r.tpm = @{ present = $t.TpmPresent; ready = $t.TpmReady } } catch { $r.tpm = $null }
try { $r.bitlocker = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus.ToString() } catch { $r.bitlocker = $null }
try { $m = Get-MpComputerStatus; $r.defender = @{ antivirus = $m.AntivirusEnabled; realtime = $m.RealTimeProtectionEnabled; signatures = $m.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd') } } catch { $r.defender = $null }
try { $r.firewall = @{}; Get-NetFirewallProfile | ForEach-Object { $r.firewall[$_.Name] = [bool]$_.Enabled } } catch { $r.firewall = $null }
try { $r.uac = [bool](Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA) } catch { $r.uac = $null }
try { $r.rdp_enabled = -not [bool](Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections) } catch { $r.rdp_enabled = $null }
try { $h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; $r.last_update = $h.InstalledOn.ToString('yyyy-MM-dd') + ' ' + $h.HotFixID } catch { $r.last_update = $null }
try { $l = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name like 'Windows%'" | Select-Object -First 1; $r.windows_activated = ($l.LicenseStatus -eq 1) } catch { $r.windows_activated = $null }
try { $r.local_admins = (Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }) -join ', ' } catch { $r.local_admins = $null }
try { $r.last_boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm') } catch { $r.last_boot = $null }
try { $r.serial = (Get-CimInstance Win32_BIOS).SerialNumber; $r.model = ((Get-CimInstance Win32_ComputerSystem).Manufacturer + ' ' + (Get-CimInstance Win32_ComputerSystem).Model).Trim() } catch { }
$r | ConvertTo-Json -Compress -Depth 4
"#;
    serde_json::from_str(&ps(script)).unwrap_or_else(|_| json!({}))
}

#[cfg(target_os = "android")]
fn security() -> Value {
    let vb = getprop("ro.boot.verifiedbootstate");
    let tags = getprop("ro.build.tags");
    let su = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su", "/data/adb/magisk"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|s| s.to_string());
    let which_su = run("sh", &["-c", "command -v su 2>/dev/null"]);
    let rooted = su.is_some() || !which_su.is_empty();
    let mut why = Vec::new();
    if vb != "green" {
        why.push(format!("verified boot: {}", if vb.is_empty() { "неизвестно" } else { &vb }));
    }
    if tags != "release-keys" {
        why.push(format!("прошивка подписана {}", if tags.is_empty() { "неизвестно" } else { &tags }));
    }
    if rooted {
        why.push("есть root (su)".to_string());
    }
    json!({
        "verified_boot": vb,
        "build_tags": tags,
        "rooted": rooted,
        "su_path": su.unwrap_or(which_su),
        "security_patch": getprop("ro.build.version.security_patch"),
        "android": getprop("ro.build.version.release"),
        "sdk": getprop("ro.build.version.sdk"),
        "fingerprint": getprop("ro.build.fingerprint"),
        "model": format!("{} {}", getprop("ro.product.manufacturer"), getprop("ro.product.model")).trim(),
        "bootloader_locked": getprop("ro.boot.flash.locked"),
        "debuggable": getprop("ro.debuggable") == "1",
        "selinux": { let s = run("getenforce", &[]); if s.is_empty() { getprop("ro.boot.selinux") } else { s } },
        "certified_guess": why.is_empty(),
        "certified_notes": why,
    })
}

#[cfg(target_os = "linux")]
fn security() -> Value {
    json!({
        "kernel": run("uname", &["-r"]),
        "distro": run("sh", &["-c", ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\""]),
        "firewall": run("sh", &["-c", "ufw status 2>/dev/null | head -1"]),
        "last_boot": run("sh", &["-c", "uptime -s 2>/dev/null"]),
        "ssh": run("sh", &["-c", "systemctl is-active ssh sshd 2>/dev/null | head -1"]),
        "updates_pending": run("sh", &["-c", "apt list --upgradable 2>/dev/null | grep -c upgradable"]),
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn security() -> Value {
    json!({
        "os": run("sw_vers", &["-productVersion"]),
        "sip": run("csrutil", &["status"]),
        "firewall": run("sh", &["-c", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null"]),
        "filevault": run("fdesetup", &["status"]),
    })
}
