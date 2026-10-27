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
pub const AUDIT_URL: &str = "https://remote.fixtech.uz/api/audit"; // + /conn, /file
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
    let v = match hbb_common::tokio::task::spawn_blocking(collect).await {
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
    refine_cpu_mem(&mut v);
    v["displays"] = displays();
    v["gpu"] = json!(gpu());
    v["storage"] = json!(storage());
    v["nics"] = nics();
    v["hardware"] = hardware();
    v["security"] = security();
    v
}

// ---- процессор и память точнее, чем у sysinfo ------------------------------------
// sysinfo отдаёт текущую частоту (на ТВ-приставке это случайный снимок, например 1.37 ГГц
// при максимуме 2.5) и память за вычетом резерва ядра. Берём максимум из cpufreq и
// MemTotal, на Android — ещё модель SoC.

fn read(path: &str) -> String {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn refine_cpu_mem(v: &mut Value) {
    let max_khz: u64 = read("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").parse().unwrap_or(0);
    let cores = num_cpus::get();
    let cpuinfo = read("/proc/cpuinfo");
    let model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name") || l.starts_with("Hardware"))
        .and_then(|l| l.split(':').nth(1))
        .map(|x| x.trim().to_string())
        .unwrap_or_default();
    #[cfg(target_os = "android")]
    let soc = {
        let m = getprop("ro.soc.model");
        let man = getprop("ro.soc.manufacturer");
        if m.is_empty() { getprop("ro.board.platform") } else if man.is_empty() { m } else { format!("{} {}", man, m) }
    };
    #[cfg(not(target_os = "android"))]
    let soc = String::new();
    let mut parts: Vec<String> = Vec::new();
    if !soc.is_empty() {
        parts.push(soc.clone());
    }
    if !model.is_empty() && !soc.contains(&model) {
        parts.push(model);
    }
    if max_khz > 0 {
        parts.push(format!("до {:.2} GHz", max_khz as f64 / 1_000_000.0));
    }
    parts.push(format!("{} ядер", cores));
    v["cpu"] = json!(parts.join(", "));
    if !soc.is_empty() {
        v["soc"] = json!(soc);
    }
    let kb: u64 = read("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with("MemTotal"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    if kb > 0 {
        let gb = kb as f64 / 1024.0 / 1024.0;
        // ближайший «паспортный» размер: 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 64 ГБ
        let nominal = [1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0, 32.0, 64.0, 128.0]
            .iter()
            .cloned()
            .find(|n| *n >= gb * 0.98)
            .unwrap_or(gb);
        v["memory"] = json!(format!("{} GB (доступно {:.2} GB)", nominal, gb));
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn refine_cpu_mem(_v: &mut Value) {}

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
        // Драйвер Mali отдаёт точную модель в sysfs; иначе — семейство из ro.hardware.egl.
        let mali = read("/sys/class/misc/mali0/device/gpuinfo");
        if !mali.is_empty() {
            return vec![mali.lines().next().unwrap_or("").trim().to_string()];
        }
        let egl = getprop("ro.hardware.egl");
        let platform = getprop("ro.board.platform");
        let mut s = String::new();
        if !egl.is_empty() {
            s.push_str(&egl);
        }
        if !platform.is_empty() {
            s.push_str(&format!(" (платформа {})", platform));
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
// Нужны все адаптеры, включая выключенные (у них тоже есть MAC и модель), поэтому
// default_net (только поднятые, без модели) дополняем: Linux/Android — sysfs,
// Windows — Get-NetAdapter. IP-адреса берём из default_net по имени интерфейса.

fn ip_map() -> std::collections::HashMap<String, (Vec<String>, Vec<String>, Option<String>)> {
    let mut m = std::collections::HashMap::new();
    #[cfg(not(target_os = "ios"))]
    for i in default_net::get_interfaces() {
        let ipv4: Vec<String> = i.ipv4.iter().map(|n| format!("{}/{}", n.addr, n.prefix_len)).collect();
        let ipv6: Vec<String> = i.ipv6.iter().map(|n| n.addr.to_string()).collect();
        let gw = i.gateway.as_ref().map(|g| g.ip_addr.to_string());
        m.insert(i.name.clone(), (ipv4.clone(), ipv6.clone(), gw.clone()));
        if let Some(f) = i.friendly_name {
            m.insert(f, (ipv4, ipv6, gw));
        }
    }
    m
}

fn phy_name(id: &str) -> &'static str {
    match id.trim() {
        "0x001cc916" => "Realtek RTL8211F (1 Гбит)",
        "0x001cc915" => "Realtek RTL8211E (1 Гбит)",
        "0x001cc816" => "Realtek RTL8201F (100 Мбит)",
        "0x001cc912" => "Realtek RTL8211D",
        "0x00008201" => "Realtek RTL8201",
        "0x0007c0f1" => "SMSC LAN8720",
        "0x20005c90" => "Amlogic внутренний PHY (100 Мбит)",
        _ => "",
    }
}

fn driver_name(drv: &str) -> &'static str {
    match drv {
        "meson8b-dwmac" | "meson6-dwmac" | "stmmaceth" => "Amlogic встроенный Ethernet (DesignWare GMAC)",
        "skw_sdio" | "skw_wifi" => "Seekwave SDIO Wi-Fi",
        "bcmdhd" | "bcmsdh_sdmmc" | "brcmfmac" => "Broadcom Wi-Fi",
        "wlan" | "cfg80211" => "",
        "rtl8822cs" | "rtl8821cs" | "8822cs" | "8821cs" => "Realtek SDIO Wi-Fi",
        "r8169" | "r8168" => "Realtek PCIe Ethernet",
        "e1000e" | "igb" | "igc" => "Intel Ethernet",
        "iwlwifi" => "Intel Wi-Fi",
        _ => "",
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn nics() -> Value {
    let ips = ip_map();
    let mut out = Vec::new();
    let skip = ["lo", "dummy", "erspan", "gre", "ifb", "ip6", "ip_vti", "sit", "tunl", "bond0", "teql"];
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).collect())
        .unwrap_or_default();
    names.sort();
    for n in names {
        if skip.iter().any(|s| n.starts_with(s)) {
            continue;
        }
        let base = format!("/sys/class/net/{}", n);
        let mac = read(&format!("{}/address", base));
        let drv = std::fs::read_link(format!("{}/device/driver", base))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()))
            .unwrap_or_default();
        let wireless = std::path::Path::new(&format!("{}/wireless", base)).exists()
            || std::path::Path::new(&format!("{}/phy80211", base)).exists();
        if mac.is_empty() || mac.starts_with("00:00:00:00") {
            continue;
        }
        if drv.is_empty() && !wireless && !ips.contains_key(&n) {
            continue; // виртуальный без драйвера и без адреса
        }
        let phy = read(&format!("{}/phydev/phy_id", base));
        let speed = read(&format!("{}/speed", base));
        let state = read(&format!("{}/operstate", base));
        let (ipv4, ipv6, gw) = ips.get(&n).cloned().unwrap_or_default();
        let mut model = driver_name(&drv).to_string();
        let phyn = phy_name(&phy);
        if !phyn.is_empty() {
            model = if model.is_empty() { phyn.to_string() } else { format!("{} + PHY {}", model, phyn) };
        }
        out.push(json!({
            "name": n,
            "type": if wireless { "Wi-Fi" } else { "Ethernet" },
            "mac": mac,
            "state": state,
            "up": state == "up",
            "link_mbps": speed.parse::<i64>().ok().filter(|x| *x > 0),
            "driver": drv,
            "phy_id": phy,
            "model": model,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gateway": gw,
        }));
    }
    json!(out)
}

#[cfg(windows)]
fn nics() -> Value {
    let ips = ip_map();
    let raw = ps(
        "Get-NetAdapter -IncludeHidden:$false | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed, DriverVersion, Virtual, MediaType, PhysicalMediaType | ConvertTo-Json -Compress",
    );
    let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let list: Vec<Value> = match parsed {
        Value::Array(a) => a,
        Value::Object(_) => vec![parsed],
        _ => vec![],
    };
    let mut out = Vec::new();
    for a in list {
        let name = a["Name"].as_str().unwrap_or("").to_string();
        let (ipv4, ipv6, gw) = ips.get(&name).cloned().unwrap_or_default();
        let media = a["PhysicalMediaType"].as_str().unwrap_or("");
        let wireless = media.contains("802.11") || media.contains("Wireless") || name.to_lowercase().contains("wi-fi");
        let status = a["Status"].as_str().unwrap_or("").to_string();
        out.push(json!({
            "name": name,
            "type": if a["Virtual"].as_bool().unwrap_or(false) { "виртуальный" } else if wireless { "Wi-Fi" } else { "Ethernet" },
            "mac": a["MacAddress"].as_str().unwrap_or("").replace('-', ":").to_lowercase(),
            "state": status,
            "up": status == "Up",
            "link": a["LinkSpeed"].as_str().unwrap_or(""),
            "driver": a["DriverVersion"].as_str().unwrap_or(""),
            "model": a["InterfaceDescription"].as_str().unwrap_or(""),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gateway": gw,
        }));
    }
    if out.is_empty() {
        // PowerShell недоступен — хотя бы поднятые интерфейсы
        for (n, (ipv4, ipv6, gw)) in ips {
            out.push(json!({ "name": n, "ipv4": ipv4, "ipv6": ipv6, "gateway": gw, "up": true }));
        }
    }
    json!(out)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn nics() -> Value {
    let ips = ip_map();
    json!(ips.into_iter().map(|(n, (ipv4, ipv6, gw))| json!({ "name": n, "ipv4": ipv4, "ipv6": ipv6, "gateway": gw, "up": true })).collect::<Vec<_>>())
}

// ---- железо ---------------------------------------------------------------------

#[cfg(windows)]
fn hardware() -> Value {
    let script = r#"
$r = [ordered]@{}
try { $b = Get-CimInstance Win32_BaseBoard; $r.board = ($b.Manufacturer + ' ' + $b.Product).Trim(); $r.board_serial = $b.SerialNumber } catch {}
try { $bi = Get-CimInstance Win32_BIOS; $r.bios = ($bi.Manufacturer + ' ' + $bi.SMBIOSBIOSVersion + ' ' + $bi.ReleaseDate.ToString('yyyy-MM-dd')).Trim() } catch {}
try { $cs = Get-CimInstance Win32_ComputerSystem; $r.model = ($cs.Manufacturer + ' ' + $cs.Model).Trim(); $r.domain = $cs.Domain } catch {}
try { $r.memory_modules = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [string][math]::Round($_.Capacity/1GB) + ' GB ' + $_.Manufacturer + ' ' + $_.PartNumber.Trim() + ' ' + $_.Speed + ' MHz ' + $_.DeviceLocator }) } catch {}
try { $r.disks = @(Get-PhysicalDisk | ForEach-Object { $_.FriendlyName + ' ' + [math]::Round($_.Size/1GB) + ' GB ' + $_.MediaType + ' ' + $_.BusType + ' (' + $_.HealthStatus + ')' }) } catch {}
if (-not $r.disks) { try { $r.disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { $_.Model + ' ' + [math]::Round($_.Size/1GB) + ' GB ' + $_.InterfaceType }) } catch {} }
try { $r.monitors = @(Get-CimInstance -Namespace root/wmi WmiMonitorID | ForEach-Object { (($_.ManufacturerName | Where-Object { $_ }) | ForEach-Object { [char]$_ }) -join '' } ) } catch {}
try { $r.monitors = @(Get-CimInstance -Namespace root/wmi WmiMonitorID | ForEach-Object { $m = (($_.ManufacturerName | ? { $_ }) | % { [char]$_ }) -join ''; $n = (($_.UserFriendlyName | ? { $_ }) | % { [char]$_ }) -join ''; $sn = (($_.SerialNumberID | ? { $_ }) | % { [char]$_ }) -join ''; ($m + ' ' + $n + ' ' + $sn).Trim() }) } catch {}
try { $r.sound = @(Get-CimInstance Win32_SoundDevice | ForEach-Object { $_.Name }) } catch {}
try { $r.usb = @(Get-PnpDevice -PresentOnly -Class USB,HIDClass,Keyboard,Mouse,Camera,Printer,Image -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -and $_.FriendlyName -notmatch 'Hub|Host Controller|Composite|Generic|Root' } | Select-Object -ExpandProperty FriendlyName -Unique) } catch {}
try { $r.printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { -not $_.Shared -or $true } | ForEach-Object { $_.Name + ' (' + $_.DriverName + ', ' + $_.PortName + ')' }) } catch {}
try { $r.battery = (Get-CimInstance Win32_Battery | Select-Object -First 1).EstimatedChargeRemaining } catch {}
try { $r.uptime_hours = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours) } catch {}
$r | ConvertTo-Json -Compress -Depth 3
"#;
    serde_json::from_str(&ps(script)).unwrap_or_else(|_| json!({}))
}

#[cfg(target_os = "android")]
fn hardware() -> Value {
    json!({
        "model": format!("{} {}", getprop("ro.product.manufacturer"), getprop("ro.product.model")).trim().to_string(),
        "board": getprop("ro.product.board"),
        "platform": getprop("ro.board.platform"),
        "bootloader": getprop("ro.bootloader"),
        "kernel": read("/proc/version").split(" (").next().unwrap_or("").replace("Linux version ", ""),
        "wifi_driver": std::fs::read_link("/sys/class/net/wlan0/device/driver").ok().and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string())).unwrap_or_default(),
        "wifi_chip": wifi_chip(),
        "bt_name": getprop("persist.btauto.name"),
        "usb": usb_devices(),
        "uptime_hours": read("/proc/uptime").split('.').next().and_then(|x| x.parse::<u64>().ok()).map(|s| s / 3600),
    })
}

#[cfg(target_os = "linux")]
fn hardware() -> Value {
    json!({
        "model": run("sh", &["-c", "cat /sys/devices/virtual/dmi/id/sys_vendor /sys/devices/virtual/dmi/id/product_name 2>/dev/null | tr '\\n' ' '"]).trim(),
        "board": run("sh", &["-c", "cat /sys/devices/virtual/dmi/id/board_vendor /sys/devices/virtual/dmi/id/board_name 2>/dev/null | tr '\\n' ' '"]).trim(),
        "bios": run("sh", &["-c", "cat /sys/devices/virtual/dmi/id/bios_vendor /sys/devices/virtual/dmi/id/bios_version /sys/devices/virtual/dmi/id/bios_date 2>/dev/null | tr '\\n' ' '"]).trim(),
        "kernel": run("uname", &["-r"]),
        "disks": lines(run("sh", &["-c", "lsblk -dno NAME,MODEL,SIZE,ROTA,TRAN 2>/dev/null | sed 's/  */ /g'"])),
        "pci": lines(run("sh", &["-c", "lspci 2>/dev/null | grep -iE 'ethernet|network|wireless' | cut -d: -f3- | sed 's/^ *//'"])),
        "usb": usb_devices(),
        "uptime_hours": read("/proc/uptime").split('.').next().and_then(|x| x.parse::<u64>().ok()).map(|s| s / 3600),
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn hardware() -> Value {
    json!({ "model": run("sysctl", &["-n", "hw.model"]) })
}

#[cfg(target_os = "android")]
fn wifi_chip() -> String {
    // Приложение не может перечислить /vendor/etc/firmware, но может проверить конкретные файлы.
    // Seekwave: EA6621 = Wi-Fi 6 1x1 + BT 5.0, EA6521 = Wi-Fi 5 + BT.
    let dirs = ["/vendor/etc/firmware", "/vendor/firmware", "/vendor/lib/firmware", "/system/etc/firmware"];
    let known: [(&str, &str); 2] = [
        ("EA6621QT_SEEKWAVE_R00005.bin", "Seekwave EA6621 (Wi-Fi 6 1x1 + BT 5.0)"),
        ("EA6521QF_SEEKWAVE_R00005.bin", "Seekwave EA6521 (Wi-Fi 5 + BT)"),
    ];
    for d in dirs {
        for (f, name) in known.iter() {
            if std::path::Path::new(&format!("{}/{}", d, f)).exists() {
                return name.to_string();
            }
        }
    }
    let name = getprop("vendor.wifi_name");
    if !name.is_empty() {
        return name;
    }
    getprop("ro.vendor.wifi.chip")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn usb_devices() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(d) = std::fs::read_dir("/sys/bus/usb/devices") {
        for e in d.filter_map(|e| e.ok()) {
            let base = e.path();
            let product = read(&format!("{}/product", base.display()));
            if product.is_empty() || product.contains("Host Controller") || product.contains("hub") || product.contains("Hub") {
                continue;
            }
            let vid = read(&format!("{}/idVendor", base.display()));
            let pid = read(&format!("{}/idProduct", base.display()));
            let man = read(&format!("{}/manufacturer", base.display()));
            out.push(format!("{} {} [{}:{}]", man, product, vid, pid).trim().to_string());
        }
    }
    out.sort();
    out.dedup();
    out
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
    let selinux = {
        let s = run("getenforce", &[]);
        if s.is_empty() { getprop("ro.boot.selinux") } else { s }
    };
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
        "model": format!("{} {}", getprop("ro.product.manufacturer"), getprop("ro.product.model")).trim().to_string(),
        "bootloader_locked": getprop("ro.boot.flash.locked"),
        "debuggable": getprop("ro.debuggable") == "1",
        "selinux": selinux,
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
