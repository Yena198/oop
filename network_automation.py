"""
NETWORK AUTOMATION SYSTEM - SINGLE FILE
Python 3.10+
Chuc nang:
- Inventory YAML: xem/them/sua/xoa/loc thiet bi
- SSH connectivity check dong thoi
- Thu thap thong tin (raw CLI output)
- Backup cau hinh, version, SHA256, SQLite
- So sanh va phat hien thay doi
- Restore an toan co xac nhan (Cisco IOS demo; cac vendor khac can adapter rieng)
- Cau hinh hang loat bang Jinja2, dry-run
- Compliance rules
- Log, bao cao Excel/CSV
- Sao luu dinh ky

LUU Y:
1. Chi chay tren thiet bi ban co quyen quan tri.
2. Kiem thu trong lab truoc khi dung mang that.
3. Restore va apply config co the lam mat ket noi. Backup truoc va doc ky output.
4. Lenh/format cau hinh khac nhau theo tung he dieu hanh. Cac adapter ben duoi la diem bat dau,
   khong phai bo tu dong hoa production da duoc kiem dinh.
"""

import os
import re
import json
import yaml
import time
import hashlib
import logging
import sqlite3
import difflib
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from dotenv import load_dotenv
from jinja2 import Template
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

try:
    from apscheduler.schedulers.blocking import BlockingScheduler
except ImportError:
    BlockingScheduler = None


# ============================================================
# 1. CAU HINH CHUNG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
INVENTORY_FILE = BASE_DIR / "devices.yaml"
RULES_FILE = BASE_DIR / "compliance_rules.yaml"
ENV_FILE = BASE_DIR / ".env"

BACKUP_DIR = BASE_DIR / "backups"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
DB_FILE = BASE_DIR / "network.db"

for folder in (BACKUP_DIR, REPORT_DIR, LOG_DIR):
    folder.mkdir(exist_ok=True)

load_dotenv(ENV_FILE)

USERNAME = os.getenv("NETWORK_USERNAME", "")
PASSWORD = os.getenv("NETWORK_PASSWORD", "")
SECRET = os.getenv("NETWORK_SECRET", "") or None

MAX_WORKERS = 5
DB_LOCK = threading.Lock()

logging.basicConfig(
    filename=str(LOG_DIR / "automation.log"),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8",
)

# Lenh thu thap theo platform. Co the bo sung theo thiet bi thuc te.
COMMANDS = {
    "cisco_ios": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "routes": "show ip route",
        "arp": "show ip arp",
        "mac": "show mac address-table",
        "neighbors": "show cdp neighbors",
        "cpu": "show processes cpu",
        "memory": "show memory",
    },
    "cisco_xe": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "routes": "show ip route",
        "arp": "show ip arp",
        "mac": "show mac address-table",
        "neighbors": "show lldp neighbors",
        "cpu": "show processes cpu",
        "memory": "show memory statistics",
    },
    "arista_eos": {
        "version": "show version",
        "interfaces": "show ip interface brief",
        "routes": "show ip route",
        "arp": "show ip arp",
        "mac": "show mac address-table",
        "neighbors": "show lldp neighbors",
        "cpu": "show processes top once",
        "memory": "show version",
    },
    "juniper_junos": {
        "version": "show version",
        "interfaces": "show interfaces terse",
        "routes": "show route",
        "arp": "show arp",
        "mac": "show ethernet-switching table",
        "neighbors": "show lldp neighbors",
        "cpu": "show system processes extensive",
        "memory": "show system memory",
    },
    "vyos": {
        "version": "show version",
        "interfaces": "show interfaces",
        "routes": "show ip route",
        "arp": "show arp",
        "mac": "show bridge macs",
        "neighbors": "show lldp neighbors",
        "cpu": "show system processes",
        "memory": "free -h",
    },
    "linux": {
        "version": "uname -a",
        "interfaces": "ip -br address",
        "routes": "ip route",
        "arp": "ip neigh",
        "mac": "ip link",
        "neighbors": "ip neigh",
        "cpu": "uptime",
        "memory": "free -h",
    },
}

# Lenh lay cau hinh theo platform.
CONFIG_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration",
    "vyos": "show configuration commands",
    # Linux can duoc backup theo cac file rieng, khong co mot lenh running-config chung.
    "linux": "cat /etc/network/interfaces",
}


# ============================================================
# 2. KHOI TAO FILE MAU VA DATABASE
# ============================================================

def create_sample_files():
    """Tao file YAML mau neu chua ton tai."""
    if not INVENTORY_FILE.exists():
        sample_inventory = {
            "devices": [
                {
                    "name": "R1",
                    "host": "192.168.1.1",
                    "port": 22,
                    "device_type": "cisco_ios",
                    "group": "routers",
                    "role": "core",
                    "tags": ["cisco", "lab"],
                },
                {
                    "name": "R2",
                    "host": "192.168.1.2",
                    "port": 22,
                    "device_type": "cisco_ios",
                    "group": "routers",
                    "role": "edge",
                    "tags": ["cisco", "lab"],
                },
            ]
        }
        with open(INVENTORY_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(sample_inventory, f, allow_unicode=True, sort_keys=False)

    if not RULES_FILE.exists():
        sample_rules = {
            "cisco_ios": [
                {"name": "SSH version 2", "pattern": r"ip ssh version 2"},
                {"name": "NTP configured", "pattern": r"(?m)^ntp server\s+"},
                {"name": "Login banner", "pattern": r"(?m)^banner motd"},
            ],
            "cisco_xe": [
                {"name": "SSH version 2", "pattern": r"ip ssh version 2"},
                {"name": "NTP configured", "pattern": r"(?m)^ntp server\s+"},
                {"name": "Login banner", "pattern": r"(?m)^banner motd"},
            ],
            "arista_eos": [
                {"name": "NTP configured", "pattern": r"(?m)^ntp server\s+"},
                {"name": "Login banner", "pattern": r"(?m)^banner motd"},
            ],
            "juniper_junos": [
                {"name": "NTP configured", "pattern": r"ntp\s*\{"},
                {"name": "SSH service", "pattern": r"ssh;"},
            ],
        }
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(sample_rules, f, allow_unicode=True, sort_keys=False)

    init_database()


def init_database():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device TEXT NOT NULL,
                backup_time TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                device TEXT,
                action TEXT,
                result TEXT,
                action_time TEXT
            )
        """)
        conn.commit()


def db_log(device, action, result):
    username = os.getenv("AUTOMATION_OPERATOR", "admin")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = str(result)[:1000]
    logging.info(
        "USER=%s | DEVICE=%s | ACTION=%s | RESULT=%s",
        username, device, action, message
    )
    with DB_LOCK:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                """INSERT INTO activity_logs
                (username, device, action, result, action_time)
                VALUES (?, ?, ?, ?, ?)""",
                (username, device, action, message, now),
            )
            conn.commit()


# ============================================================
# 3. INVENTORY
# ============================================================

def load_devices():
    if not INVENTORY_FILE.exists():
        create_sample_files()
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("devices", [])


def save_devices(devices):
    with open(INVENTORY_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            {"devices": devices},
            f,
            allow_unicode=True,
            sort_keys=False,
        )


def display_devices(devices=None):
    devices = devices if devices is not None else load_devices()
    if not devices:
        print("Inventory dang trong.")
        return

    print("\n{:<12} {:<18} {:<18} {:<12} {:<12}".format(
        "NAME", "HOST", "PLATFORM", "GROUP", "ROLE"
    ))
    print("-" * 76)
    for d in devices:
        print("{:<12} {:<18} {:<18} {:<12} {:<12}".format(
            d.get("name", ""),
            d.get("host", ""),
            d.get("device_type", ""),
            d.get("group", ""),
            d.get("role", ""),
        ))


def inventory_menu():
    while True:
        print("\n--- INVENTORY ---")
        print("1. Xem danh sach")
        print("2. Them thiet bi")
        print("3. Sua IP/group/role")
        print("4. Xoa thiet bi")
        print("5. Loc theo group/role/tag")
        print("0. Quay lai")
        choice = input("Chon: ").strip()

        devices = load_devices()

        if choice == "1":
            display_devices(devices)

        elif choice == "2":
            name = input("Ten thiet bi: ").strip()
            if not name or any(d.get("name") == name for d in devices):
                print("Ten rong hoac da ton tai.")
                continue
            host = input("IP/hostname: ").strip()
            platform = input(
                "Platform (cisco_ios/cisco_xe/arista_eos/"
                "juniper_junos/vyos/linux): "
            ).strip()
            try:
                port = int(input("SSH port [22]: ").strip() or "22")
            except ValueError:
                print("Port khong hop le.")
                continue
            new_device = {
                "name": name,
                "host": host,
                "port": port,
                "device_type": platform,
                "group": input("Group: ").strip(),
                "role": input("Role: ").strip(),
                "tags": [
                    x.strip() for x in input("Tags, cach nhau boi dau phay: ").split(",")
                    if x.strip()
                ],
            }
            devices.append(new_device)
            save_devices(devices)
            print("Da them thiet bi.")

        elif choice == "3":
            name = input("Ten thiet bi can sua: ").strip()
            device = next((d for d in devices if d.get("name") == name), None)
            if not device:
                print("Khong tim thay.")
                continue
            host = input(f"IP moi [{device.get('host')}]: ").strip()
            group = input(f"Group moi [{device.get('group')}]: ").strip()
            role = input(f"Role moi [{device.get('role')}]: ").strip()
            if host:
                device["host"] = host
            if group:
                device["group"] = group
            if role:
                device["role"] = role
            save_devices(devices)
            print("Da cap nhat.")

        elif choice == "4":
            name = input("Ten thiet bi can xoa: ").strip()
            new_devices = [d for d in devices if d.get("name") != name]
            if len(new_devices) == len(devices):
                print("Khong tim thay.")
            else:
                save_devices(new_devices)
                print("Da xoa.")

        elif choice == "5":
            group = input("Group (Enter bo qua): ").strip()
            role = input("Role (Enter bo qua): ").strip()
            tag = input("Tag (Enter bo qua): ").strip()
            result = []
            for d in devices:
                if group and d.get("group") != group:
                    continue
                if role and d.get("role") != role:
                    continue
                if tag and tag not in d.get("tags", []):
                    continue
                result.append(d)
            display_devices(result)

        elif choice == "0":
            return
        else:
            print("Lua chon khong hop le.")


# ============================================================
# 4. SSH CONNECTION
# ============================================================

def connect_device(device):
    if not USERNAME or not PASSWORD:
        print("Thieu NETWORK_USERNAME/NETWORK_PASSWORD trong file .env")
        return None

    params = {
        "device_type": device["device_type"],
        "host": device["host"],
        "port": int(device.get("port", 22)),
        "username": USERNAME,
        "password": PASSWORD,
        "conn_timeout": 10,
        "auth_timeout": 10,
        "banner_timeout": 15,
        "fast_cli": False,
    }

    if SECRET:
        params["secret"] = SECRET

    try:
        connection = ConnectHandler(**params)
        # Cisco enable neu co secret
        if SECRET and device["device_type"] in ("cisco_ios", "cisco_xe"):
            try:
                connection.enable()
            except Exception:
                pass
        return connection

    except NetmikoAuthenticationException:
        print(f"[AUTH ERROR] {device['name']}: Sai tai khoan/mat khau.")
        db_log(device["name"], "CONNECT", "AUTH ERROR")
    except NetmikoTimeoutException:
        print(f"[TIMEOUT] {device['name']}: Khong phan hoi.")
        db_log(device["name"], "CONNECT", "TIMEOUT")
    except Exception as exc:
        print(f"[ERROR] {device['name']}: {exc}")
        db_log(device["name"], "CONNECT", f"ERROR: {exc}")
    return None


def check_one_device(device):
    conn = connect_device(device)
    if conn:
        try:
            conn.disconnect()
        except Exception:
            pass
        db_log(device["name"], "CONNECT", "ONLINE")
        return {"device": device["name"], "ip": device["host"], "status": "ONLINE"}
    return {"device": device["name"], "ip": device["host"], "status": "OFFLINE"}


def check_all_devices():
    devices = load_devices()
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(check_one_device, d) for d in devices]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"device": "unknown", "ip": "", "status": str(exc)})

    print("\nKET QUA KIEM TRA SSH")
    for r in sorted(results, key=lambda x: x["device"]):
        print(f"{r['device']:<12} {r['ip']:<18} {r['status']}")
    return results


# ============================================================
# 5. BACKUP / VERSION / HASH
# ============================================================

def get_config_command(device):
    platform = device["device_type"]
    if platform not in CONFIG_COMMANDS:
        raise ValueError(f"Chua ho tro backup cho platform: {platform}")
    return CONFIG_COMMANDS[platform]


def backup_device(device):
    conn = connect_device(device)
    if not conn:
        return None

    try:
        command = get_config_command(device)
        config = conn.send_command(command, read_timeout=60)

        if not config or "Invalid input" in config or "unknown command" in config.lower():
            raise RuntimeError(f"Khong lay duoc cau hinh bang lenh: {command}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        device_folder = BACKUP_DIR / device["name"]
        device_folder.mkdir(parents=True, exist_ok=True)
        file_path = device_folder / f"{timestamp}.cfg"

        file_path.write_text(config, encoding="utf-8")
        digest = hashlib.sha256(config.encode("utf-8")).hexdigest()

        with DB_LOCK:
            with sqlite3.connect(DB_FILE) as db:
                db.execute(
                    """INSERT INTO backups
                    (device, backup_time, file_path, file_hash, status)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        device["name"],
                        timestamp,
                        str(file_path),
                        digest,
                        "SUCCESS",
                    ),
                )
                db.commit()

        db_log(device["name"], "BACKUP", "SUCCESS")
        print(f"[BACKUP OK] {device['name']} -> {file_path}")
        return str(file_path)

    except Exception as exc:
        print(f"[BACKUP ERROR] {device['name']}: {exc}")
        db_log(device["name"], "BACKUP", f"FAILED: {exc}")
        return None

    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def backup_all(devices=None):
    devices = devices if devices is not None else load_devices()
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(backup_device, d): d for d in devices}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                print("Backup task error:", exc)
    return results


def list_backups(device_name=None):
    with sqlite3.connect(DB_FILE) as db:
        if device_name:
            rows = db.execute(
                """SELECT id, device, backup_time, file_path, file_hash, status
                FROM backups WHERE device=? ORDER BY id DESC""",
                (device_name,),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT id, device, backup_time, file_path, file_hash, status
                FROM backups ORDER BY id DESC"""
            ).fetchall()

    if not rows:
        print("Chua co ban backup trong database.")
        return []

    print("\n{:<5} {:<12} {:<18} {:<10} {}".format(
        "ID", "DEVICE", "TIME", "STATUS", "FILE"
    ))
    print("-" * 95)
    for row in rows:
        print("{:<5} {:<12} {:<18} {:<10} {}".format(
            row[0], row[1], row[2], row[5], row[3]
        ))
    return rows


def latest_backup_path(device_name):
    rows = list_backups_for_device(device_name)
    return rows[0][0] if rows else None


def list_backups_for_device(device_name):
    with sqlite3.connect(DB_FILE) as db:
        rows = db.execute(
            """SELECT file_path, backup_time, file_hash
            FROM backups WHERE device=? AND status='SUCCESS'
            ORDER BY backup_time DESC""",
            (device_name,),
        ).fetchall()
    return rows


# ============================================================
# 6. COMPARE / CHANGE DETECTION
# ============================================================

def compare_files(old_file, new_file):
    old_path = Path(old_file)
    new_path = Path(new_file)

    if not old_path.is_file() or not new_path.is_file():
        print("Khong tim thay mot trong hai file.")
        return []

    old_lines = old_path.read_text(encoding="utf-8", errors="replace").splitlines(True)
    new_lines = new_path.read_text(encoding="utf-8", errors="replace").splitlines(True)

    diff = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=str(old_path),
        tofile=str(new_path),
    ))

    if diff:
        print("\n".join(line.rstrip("\n") for line in diff))
    else:
        print("Hai phien ban giong nhau.")
    return diff


def detect_change(device):
    current_file = backup_device(device)
    if not current_file:
        return

    backups = list_backups_for_device(device["name"])
    # Vi backup_device vua tao ban moi, so sanh voi ban truoc do.
    if len(backups) < 2:
        print(f"{device['name']}: Day la ban backup dau tien, chua co ban de so sanh.")
        return

    previous_file = backups[1][0]
    diff = compare_files(previous_file, current_file)

    if diff:
        print(f"[WARNING] Phat hien thay doi tren {device['name']}")
        db_log(device["name"], "CHANGE_DETECTION", "CHANGED")
    else:
        print(f"[OK] {device['name']}: Khong thay doi")
        db_log(device["name"], "CHANGE_DETECTION", "NO CHANGE")


def detect_all_changes():
    for device in load_devices():
        try:
            detect_change(device)
        except Exception as exc:
            print(f"[DETECT ERROR] {device['name']}: {exc}")


# ============================================================
# 7. RESTORE - CAN THAN TRONG
# ============================================================

def restore_config():
    print("\nCANH BAO: Restore co the lam mat ket noi quan tri.")
    device_name = input("Ten thiet bi: ").strip()
    device = next(
        (d for d in load_devices() if d.get("name") == device_name),
        None
    )

    if not device:
        print("Khong tim thay thiet bi.")
        return

    backups = list_backups_for_device(device_name)
    if not backups:
        print("Thiet bi chua co backup.")
        return

    print("\nCac ban backup:")
    for index, item in enumerate(backups, start=1):
        print(f"{index}. {item[1]} | {item[0]}")

    try:
        selected = int(input("Chon ban backup: "))
        backup_file = backups[selected - 1][0]
    except (ValueError, IndexError):
        print("Lua chon khong hop le.")
        return

    if device["device_type"] not in ("cisco_ios", "cisco_xe"):
        print(
            "Ban restore mau nay chi minh hoa cho Cisco IOS/IOS-XE. "
            "Juniper/Arista/VyOS/Linux can adapter restore rieng."
        )
        return

    print(
        "Luu y: lenh configure replace chi hoat dong tren mot so "
        "phien ban Cisco IOS/IOS-XE va can file backup nam tren flash:"
    )
    remote_file = input("Duong dan file tren flash (vi du flash:backup.cfg): ").strip()
    if not remote_file.startswith(("flash:", "bootflash:")):
        print("Hay nhap duong dan flash:/bootflash: hop le.")
        return

    confirm = input(
        f"GO RESTORE {device_name} tu {backup_file}? Nhap YES de xac nhan: "
    ).strip()

    if confirm != "YES":
        print("Da huy.")
        return

    # Tao backup trang thai hien tai truoc khi restore.
    pre_restore = backup_device(device)
    if not pre_restore:
        print("Khong the backup trang thai hien tai. Huy restore.")
        return

    conn = connect_device(device)
    if not conn:
        return

    try:
        # Khong tu dong upload file qua SCP o ban khung nay.
        # Quan tri vien phai chuyen file backup len flash truoc.
        output = conn.send_command_timing(
            f"configure replace {remote_file} force",
            read_timeout=180,
        )
        print(output)
        db_log(device_name, "RESTORE", "COMMAND_SENT - NEED VERIFY")
        print("Da gui lenh. Hay kiem tra lai running-config va ket noi.")
    except Exception as exc:
        print("Restore error:", exc)
        db_log(device_name, "RESTORE", f"FAILED: {exc}")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


# ============================================================
# 8. MONITORING / THU THAP THONG TIN
# ============================================================

def collect_device_info(device):
    conn = connect_device(device)
    if not conn:
        return None

    try:
        platform = device["device_type"]
        commands = COMMANDS.get(platform)

        if not commands:
            raise ValueError(f"Chua co bo lenh monitoring cho {platform}")

        result = {
            "device": device["name"],
            "host": device["host"],
            "platform": platform,
            "collected_at": datetime.now().isoformat(timespec="seconds"),
            "information": {},
        }

        for key, command in commands.items():
            try:
                result["information"][key] = conn.send_command(
                    command,
                    read_timeout=60,
                )
            except Exception as exc:
                result["information"][key] = {
                    "error": str(exc)
                }

        return result

    except Exception as exc:
        print(f"[MONITOR ERROR] {device['name']}: {exc}")
        return None

    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def monitoring_all():
    results = []
    devices = load_devices()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(collect_device_info, d) for d in devices]
        for future in as_completed(futures):
            try:
                data = future.result()
                if data:
                    results.append(data)
            except Exception as exc:
                print("Monitoring task error:", exc)

    output_file = REPORT_DIR / (
        "monitoring_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
    )
    output_file.write_text(
        json.dumps(results, ensure_ascii=False, indent=4),
        encoding="utf-8",
    )
    print("Da xuat JSON:", output_file)
    return results


# ============================================================
# 9. CONFIGURATION BANG JINJA2
# ============================================================

def configure_batch():
    devices = load_devices()
    group = input("Nhap group can cau hinh (Enter = tat ca): ").strip()

    if group:
        devices = [d for d in devices if d.get("group") == group]

    if not devices:
        print("Khong co thiet bi phu hop.")
        return

    print("\nNhap template Jinja2. Ket thuc bang mot dong chi co END.")
    print("Vi du Cisco VLAN:")
    print("vlan {{ vlan_id }}")
    print(" name {{ vlan_name }}")
    print("END")

    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)

    template_text = "\n".join(lines)

    variables = {}
    print("Nhap bien template theo dang key=value.")
    print("Vi du: vlan_id=10")
    print("Nhap END de ket thuc.")

    while True:
        item = input("Variable: ").strip()
        if item.upper() == "END":
            break
        if "=" in item:
            key, value = item.split("=", 1)
            variables[key.strip()] = value.strip()

    try:
        rendered_config = Template(template_text).render(**variables)
    except Exception as exc:
        print("Loi render template:", exc)
        return

    print("\n===== CONFIG DU KIEN =====")
    print(rendered_config)
    print("==========================")

    dry_run = input("Dry-run? (Y/n): ").strip().lower() != "n"
    if dry_run:
        print("DRY-RUN: Khong gui cau hinh den thiet bi.")
        return

    confirm = input("Xac nhan ap dung tren cac thiet bi? Nhap APPLY: ").strip()
    if confirm != "APPLY":
        print("Da huy.")
        return

    for device in devices:
        if device["device_type"] not in (
            "cisco_ios", "cisco_xe", "arista_eos"
        ):
            print(
                f"[SKIP] {device['name']}: adapter apply mau chi danh cho "
                "Cisco IOS/IOS-XE va Arista EOS."
            )
            continue

        # Backup truoc khi thay doi.
        if not backup_device(device):
            print(f"[SKIP] {device['name']}: backup truoc thay doi that bai.")
            continue

        conn = connect_device(device)
        if not conn:
            continue

        try:
            output = conn.send_config_set(
                rendered_config.splitlines(),
                read_timeout=90,
            )
            print(f"\n[{device['name']}]")
            print(output)
            db_log(device["name"], "CONFIG_APPLY", "COMMAND_SENT - NEED VERIFY")
        except Exception as exc:
            print(f"[CONFIG ERROR] {device['name']}: {exc}")
            db_log(device["name"], "CONFIG_APPLY", f"FAILED: {exc}")
            print(
                "Can rollback thu cong tu ban backup truoc thay doi. "
                "Khong tu dong rollback vi moi platform co co che khac nhau."
            )
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass


# ============================================================
# 10. COMPLIANCE
# ============================================================

def load_compliance_rules():
    if not RULES_FILE.exists():
        create_sample_files()
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def compliance_check():
    rules_by_platform = load_compliance_rules()
    rows = []

    for device in load_devices():
        backups = list_backups_for_device(device["name"])

        if not backups:
            rows.append({
                "device": device["name"],
                "rule": "Configuration backup",
                "status": "NO BACKUP",
            })
            continue

        config_file = Path(backups[0][0])
        if not config_file.exists():
            continue

        config = config_file.read_text(encoding="utf-8", errors="replace")
        rules = rules_by_platform.get(device["device_type"], [])

        if not rules:
            rows.append({
                "device": device["name"],
                "rule": "Compliance rules",
                "status": "NOT DEFINED",
            })
            continue

        for rule in rules:
            try:
                passed = re.search(
                    rule["pattern"],
                    config,
                    flags=re.IGNORECASE | re.MULTILINE,
                ) is not None
                rows.append({
                    "device": device["name"],
                    "rule": rule["name"],
                    "status": "PASS" if passed else "FAIL",
                })
            except re.error as exc:
                rows.append({
                    "device": device["name"],
                    "rule": rule.get("name", "Unknown"),
                    "status": f"INVALID RULE: {exc}",
                })

    if rows:
        df = pd.DataFrame(rows)
        output = REPORT_DIR / (
            "compliance_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".xlsx"
        )
        df.to_excel(output, index=False)
        print(df.to_string(index=False))
        print("Da xuat compliance report:", output)
    else:
        print("Khong co du lieu compliance.")


# ============================================================
# 11. REPORT / EXPORT LOG
# ============================================================

def export_backup_report():
    with sqlite3.connect(DB_FILE) as db:
        df = pd.read_sql_query(
            "SELECT * FROM backups ORDER BY backup_time DESC",
            db,
        )

    if df.empty:
        print("Chua co du lieu backup.")
        return

    output = REPORT_DIR / (
        "backup_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".xlsx"
    )
    df.to_excel(output, index=False)
    print("Da xuat:", output)


def export_activity_report():
    with sqlite3.connect(DB_FILE) as db:
        df = pd.read_sql_query(
            "SELECT * FROM activity_logs ORDER BY action_time DESC",
            db,
        )

    if df.empty:
        print("Chua co activity log.")
        return

    output = REPORT_DIR / (
        "activity_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".xlsx"
    )
    df.to_excel(output, index=False)
    print("Da xuat:", output)


# ============================================================
# 12. SCHEDULER
# ============================================================

def run_scheduler():
    if BlockingScheduler is None:
        print("Chua cai apscheduler. Chay: pip install apscheduler")
        return

    scheduler = BlockingScheduler()

    def job():
        print("\n[ SCHEDULED BACKUP ]")
        backup_all()

    scheduler.add_job(
        job,
        trigger="cron",
        hour=2,
        minute=0,
        id="daily_network_backup",
        replace_existing=True,
    )

    print("Scheduler dang chay. Backup moi ngay luc 02:00.")
    print("Nhan Ctrl+C de dung.")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("Da dung scheduler.")


# ============================================================
# 13. MENU CHINH
# ============================================================

def main():
    create_sample_files()

    while True:
        print("\n" + "=" * 55)
        print("       NETWORK AUTOMATION SYSTEM")
        print("=" * 55)
        print("1.  Quan ly Inventory")
        print("2.  Kiem tra SSH tat ca thiet bi")
        print("3.  Thu thap thong tin thiet bi")
        print("4.  Sao luu cau hinh")
        print("5.  Xem lich su backup")
        print("6.  So sanh hai file cau hinh")
        print("7.  Phat hien thay doi (backup va so sanh)")
        print("8.  Khoi phuc cau hinh")
        print("9.  Cau hinh hang loat bang Jinja2")
        print("10. Kiem tra Compliance")
        print("11. Xuat bao cao backup Excel")
        print("12. Xuat bao cao activity Excel")
        print("13. Bat dau sao luu dinh ky (02:00 moi ngay)")
        print("0.  Thoat")
        print("=" * 55)

        choice = input("Chon chuc nang: ").strip()

        try:
            if choice == "1":
                inventory_menu()

            elif choice == "2":
                check_all_devices()

            elif choice == "3":
                monitoring_all()

            elif choice == "4":
                backup_all()

            elif choice == "5":
                name = input("Ten thiet bi (Enter = tat ca): ").strip()
                list_backups(name if name else None)

            elif choice == "6":
                old_file = input("Duong dan file cu: ").strip()
                new_file = input("Duong dan file moi: ").strip()
                compare_files(old_file, new_file)

            elif choice == "7":
                detect_all_changes()

            elif choice == "8":
                restore_config()

            elif choice == "9":
                configure_batch()

            elif choice == "10":
                compliance_check()

            elif choice == "11":
                export_backup_report()

            elif choice == "12":
                export_activity_report()

            elif choice == "13":
                run_scheduler()

            elif choice == "0":
                print("Ket thuc chuong trinh.")
                break

            else:
                print("Lua chon khong hop le.")

        except KeyboardInterrupt:
            print("\nTac vu bi huy boi nguoi dung.")
        except Exception as exc:
            logging.exception("Unexpected error")
            print("Da xay ra loi:", exc)


if __name__ == "__main__":
    main()
