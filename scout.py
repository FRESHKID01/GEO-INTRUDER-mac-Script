import os
import re
import sys
import time
import uuid
import platform
import subprocess
import requests
import cv2
from multiprocessing import freeze_support

# ==========================================
# PRODUCTION CONFIGURATION
# ==========================================
# Update this to your public domain or ngrok URL when deploying
SERVER_URL = "http://localhost/GEO_INTRUDER/process_breach.php"

# Detect Operating System ('Windows', 'Linux', or 'Darwin')
OS_TYPE = platform.system()

# Cross-Platform Hidden Evidence Directory
if OS_TYPE == "Windows":
    HIDDEN_DIR = "C:/Windows/Temp/SystemDiagnosticLogs/"
else:
    HIDDEN_DIR = "/tmp/.system_diagnostic_logs/"

if not os.path.exists(HIDDEN_DIR):
    try:
        os.makedirs(HIDDEN_DIR, exist_ok=True)
    except Exception:
        HIDDEN_DIR = "./"

breach_check_count = 0


# ==========================================
# CROSS-PLATFORM PERSISTENCE SETUP
# ==========================================
def install_cross_platform_persistence():
    """Configures background startup persistence based on the target OS."""
    try:
        app_path = os.path.realpath(sys.argv[0])

        if OS_TYPE == "Windows":
            # Safely import winreg only on Windows
            import winreg
            registry_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_WRITE
            )
            winreg.SetValueEx(registry_key, "AssetGuardScout", 0, winreg.REG_SZ, app_path)
            winreg.CloseKey(registry_key)

        elif OS_TYPE == "Darwin":  # macOS LaunchAgent
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.assetguard.scout</string>
    <key>ProgramArguments</key>
    <array>
        <string>{app_path}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>"""
            launch_dir = os.path.expanduser("~/Library/LaunchAgents")
            os.makedirs(launch_dir, exist_ok=True)
            plist_path = os.path.join(launch_dir, "com.assetguard.scout.plist")
            if not os.path.exists(plist_path):
                with open(plist_path, "w") as f:
                    f.write(plist_content)

        elif OS_TYPE == "Linux":  # Linux / Kali Desktop Autostart
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=AssetGuardScout
Exec={app_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            desktop_path = os.path.join(autostart_dir, "assetguard.desktop")
            if not os.path.exists(desktop_path):
                with open(desktop_path, "w") as f:
                    f.write(desktop_content)

    except Exception as e:
        # Fail silently to avoid alerting end-user or interrupting main execution loop
        pass


# ==========================================
# EVIDENCE CAPTURE & TELEMETRY
# ==========================================
def capture_intruder_image():
    """Captures a webcam frame using OS-appropriate video capture flags with warm-up frames."""
    cap = None
    try:
        # DirectShow on Windows, default native backend on Linux/macOS
        if OS_TYPE == "Windows":
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        else:
            cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            return None

        # Warm-up delay + discard early dark frames for camera auto-exposure
        time.sleep(0.6)
        for _ in range(5):
            cap.grab()

        ret, frame = cap.read()
        cap.release()
        cap = None

        if ret and frame is not None:
            image_filename = os.path.join(HIDDEN_DIR, f"snap_{int(time.time())}.jpg")
            cv2.imwrite(image_filename, frame)
            return image_filename
    except Exception as e:
        print(f"[-] Webcam error: {e}")
    finally:
        if cap is not None and cap.isOpened():
            cap.release()
    return None


def get_ethernet_mac():
    """Extracts wired Ethernet MAC address per OS platform."""
    try:
        if OS_TYPE == "Windows":
            out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
            blocks = out.split("\n\n")
            for block in blocks:
                if "Ethernet adapter" in block or "Local Area Connection" in block:
                    mac_match = re.search(r'Physical Address[^\:]*:\s*([0-9a-fA-F:-]{17})', block)
                    if mac_match:
                        return mac_match.group(1).replace('-', ':').upper()

        elif OS_TYPE == "Linux":
            for iface in os.listdir('/sys/class/net/'):
                if iface.startswith(('eth', 'enp', 'eno', 'end')):
                    addr_path = f'/sys/class/net/{iface}/address'
                    if os.path.exists(addr_path):
                        with open(addr_path, 'r') as f:
                            mac = f.read().strip().upper()
                            if mac and mac != "00:00:00:00:00:00":
                                return mac

        elif OS_TYPE == "Darwin":
            out = subprocess.check_output(['ifconfig'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
            interfaces = re.findall(r'^(en\d+):.*?\n(?=\S|$)', out, re.MULTILINE | re.DOTALL)
            for iface_block in interfaces:
                if 'ether' in iface_block and 'status: active' in iface_block:
                    mac_match = re.search(r'ether\s+([0-9a-fA-F:]{17})', iface_block)
                    if mac_match:
                        return mac_match.group(1).upper()
    except Exception:
        pass
    return None


def get_wifi_telemetry():
    """Extracts Wi-Fi MAC and connected BSSID per OS."""
    wifi_mac = None
    wifi_bssid = None

    try:
        if OS_TYPE == "Windows":
            out = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
            bssid_match = re.search(r'BSSID\s*:\s*([0-9a-fA-F:]{17})', out)
            mac_match = re.search(r'Physical address\s*:\s*([0-9a-fA-F:]{17})', out)
            if mac_match:
                wifi_mac = mac_match.group(1).upper()
            if bssid_match:
                wifi_bssid = bssid_match.group(1).upper()

        elif OS_TYPE == "Linux":
            # Attempt 1: iwconfig
            try:
                out = subprocess.check_output(['iwconfig'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
                bssid_match = re.search(r'Access Point:\s*([0-9a-fA-F:]{17})', out)
                if bssid_match and bssid_match.group(1) != "Not-Associated":
                    wifi_bssid = bssid_match.group(1).upper()
            except Exception:
                pass

            # Attempt 2: nmcli fallback (common on Kali)
            if not wifi_bssid:
                try:
                    out = subprocess.check_output(['nmcli', '-t', '-f', 'active,bssid', 'dev', 'wifi'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
                    for line in out.splitlines():
                        if line.startswith('yes:'):
                            wifi_bssid = line.split('yes:')[1].strip().replace('\\', '').upper()
                            break
                except Exception:
                    pass

            # Attempt 3: iw dev fallback
            if not wifi_bssid:
                try:
                    out = subprocess.check_output(['iw', 'dev'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
                    bssid_match = re.search(r'addr\s+([0-9a-fA-F:]{17})', out)
                    if bssid_match:
                        wifi_bssid = bssid_match.group(1).upper()
                except Exception:
                    pass

            # Read Wi-Fi interface MAC directly from sysfs
            try:
                for iface in os.listdir('/sys/class/net/'):
                    if iface.startswith(('wlan', 'wlp', 'wls')):
                        addr_path = f'/sys/class/net/{iface}/address'
                        if os.path.exists(addr_path):
                            with open(addr_path, 'r') as f:
                                wifi_mac = f.read().strip().upper()
                                if wifi_mac:
                                    break
            except Exception:
                pass

        elif OS_TYPE == "Darwin":  # macOS
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport_path):
                try:
                    out = subprocess.check_output([airport_path, '-I'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
                    bssid_match = re.search(r'BSSID:\s*([0-9a-fA-F:]{17})', out)
                    if bssid_match:
                        wifi_bssid = bssid_match.group(1).upper()
                except Exception:
                    pass

            # Read Wi-Fi MAC address on macOS
            try:
                out_if = subprocess.check_output(['ifconfig', 'en0'], text=True, errors='ignore', stderr=subprocess.DEVNULL)
                mac_match = re.search(r'ether\s+([0-9a-fA-F:]{17})', out_if)
                if mac_match:
                    wifi_mac = mac_match.group(1).upper()
            except Exception:
                pass

    except Exception:
        pass

    return wifi_mac, wifi_bssid


def get_network_telemetry():
    """Builds a unified hardware network footprint based on OS."""
    wifi_mac, wifi_bssid = get_wifi_telemetry()
    wired_mac = get_ethernet_mac()

    if wifi_bssid and wifi_bssid != "00:00:00:00:00:00":
        active_mac = wifi_mac or wired_mac
        return {
            "wifi_mac": wifi_mac,
            "ethernet_mac": wired_mac,
            "active_mac": active_mac,
            "current_anchor": wifi_bssid,
            "mode": "WIRELESS"
        }
    else:
        fallback_mac = wifi_mac or wired_mac or ":".join(hex(uuid.getnode())[2:].zfill(12)[i:i+2] for i in range(0, 12, 2)).upper()
        return {
            "wifi_mac": wifi_mac,
            "ethernet_mac": wired_mac,
            "active_mac": fallback_mac,
            "current_anchor": "00:00:00:00:00:00",
            "mode": "DISCONNECTED" if not wired_mac else "WIRED"
        }


# ==========================================
# MAIN EXECUTION LOOP
# ==========================================
def main_security_loop():
    global breach_check_count
    print(f"[+] Asset-Guard active on platform: [{OS_TYPE}]")

    while True:
        telemetry = get_network_telemetry()
        check_interval = 15

        payload = {
            "wifi_mac": telemetry["wifi_mac"] or "",
            "ethernet_mac": telemetry["ethernet_mac"] or "",
            "active_mac": telemetry["active_mac"] or "",
            "current_anchor": telemetry["current_anchor"] or "",
            "mode": telemetry["mode"],
            "os_platform": OS_TYPE
        }

        img_path = None
        
        # Pre-capture webcam evidence if location anchor is missing/invalid or breach count active
        if telemetry["current_anchor"] == "00:00:00:00:00:00" or breach_check_count > 0:
            img_path = capture_intruder_image()

        try:
            if img_path and os.path.exists(img_path):
                img_name = os.path.basename(img_path)
                payload["image_name"] = img_name
                
                with open(img_path, 'rb') as img_file:
                    files = {'intruder_img': (img_name, img_file, 'image/jpeg')}
                    response = requests.post(SERVER_URL, data=payload, files=files, timeout=15)
            else:
                response = requests.post(SERVER_URL, data=payload, timeout=10)

            if response.status_code == 200:
                try:
                    server_data = response.json()
                    status = str(server_data.get("status")).lower()

                    if status in ["secure", "clear"]:
                        print(f"[*] [{telemetry['mode']} | {OS_TYPE}] CLEAR. Active MAC: {telemetry['active_mac']} | Heartbeat OK.")
                        breach_check_count = 0
                        check_interval = 15

                    elif status in ["breach", "breached", "processed"]:
                        breach_check_count += 1
                        if breach_check_count <= 5:
                            print(f"[!] BREACH ALERT [{OS_TYPE}]: Cycle {breach_check_count}/5. Re-checking in 60s.")
                            check_interval = 60
                        else:
                            print(f"[!] BREACH ALERT [{OS_TYPE}]: Production Throttle engaged (600s).")
                            check_interval = 600
                    else:
                        print(f"[*] [{telemetry['mode']} | {OS_TYPE}] Status: {status}")

                except ValueError:
                    print(f"[-] Server returned invalid JSON response (Status {response.status_code}).")
            else:
                print(f"[-] Server responded with HTTP status {response.status_code}.")

        except Exception as error:
            print(f"[-] Network connection error: {error}")

        finally:
            if img_path and os.path.exists(img_path):
                try:
                    os.remove(img_path)
                except Exception as e:
                    print(f"[-] File cleanup warning: {e}")

        time.sleep(check_interval)


if __name__ == '__main__':
    freeze_support()
    install_cross_platform_persistence()  # Registers auto-start silently on initial launch
    main_security_loop()