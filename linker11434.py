#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
import psutil

try:
    import gi
    gi.require_version("AppIndicator3", "0.1")
    from gi.repository import AppIndicator3, Gtk, GLib
    from PIL import Image, ImageDraw
except ImportError:
    print("ERROR: Requires AppIndicator3 and PIL libraries.")
    sys.exit(1)

###############################################################################
# Common bridging logic
###############################################################################

def is_socat_active_on_11434():
    """Return True if a socat process is listening on port 11434."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = (proc.info['name'] or "").lower()
            cmdline = proc.info['cmdline'] or []
            cmd_str = " ".join(cmdline).lower()
            if 'socat' in name or 'socat' in cmd_str:
                for conn in psutil.net_connections(kind='inet'):
                    if (conn.pid == proc.pid and
                        conn.laddr and
                        conn.laddr.port == 11434 and
                        conn.status == psutil.CONN_LISTEN):
                        return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def get_private_ips():
    """Return all private IPs (192.168.x.x or 10.x.x.x)."""
    private_ips = set()
    for iface, addr_info in psutil.net_if_addrs().items():
        for addr in addr_info:
            if addr.family == 2:  # AF_INET
                ip = addr.address
                if ip.startswith("192.168.") or ip.startswith("10."):
                    private_ips.add(ip)
    return sorted(private_ips)

def enable_bridge():
    """Enable Ollama bridging by launching socat for each private IP."""
    if is_socat_active_on_11434():
        return  # Already running
    private_ips = get_private_ips()
    if not private_ips:
        print("[OllamaBridge] No private IPs detected.")
    else:
        for ip in private_ips:
            cmd = [
                "socat",
                f"TCP-LISTEN:11434,fork,bind={ip}",
                "TCP:127.0.0.1:11434",
            ]
            try:
                subprocess.Popen(cmd)  # async
                print(f"[OllamaBridge] Started bridging on {ip} => 127.0.0.1:11434")
            except Exception as e:
                print(f"[OllamaBridge] Error launching socat on {ip}: {e}")

def disable_bridge():
    """Kill all socat processes that are bound to port 11434."""
    killed_any = False
    # (1) Attempt lsof first
    try:
        pids_output = subprocess.check_output(
            ["lsof", "-t", "-i", "TCP:11434"], stderr=subprocess.STDOUT
        )
        pids = pids_output.decode().strip().split()
        for pid_str in pids:
            if pid_str.isdigit():
                pid = int(pid_str)
                try:
                    proc = psutil.Process(pid)
                    if proc.name().lower() == "socat":
                        os.kill(pid, signal.SIGKILL)
                        killed_any = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # (2) Double-check with psutil
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = (proc.info['name'] or "").lower()
            cmdline = proc.info['cmdline'] or []
            cmd_str = " ".join(cmdline).lower()
            if 'socat' in name or 'socat' in cmd_str:
                for conn in psutil.net_connections(kind='inet'):
                    if (conn.pid == proc.pid and
                        conn.laddr.port == 11434 and
                        conn.status == psutil.CONN_LISTEN):
                        proc.kill()
                        killed_any = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if killed_any:
        print("[OllamaBridge] All socat processes on port 11434 were killed.")
    else:
        print("[OllamaBridge] No active socat processes found on port 11434.")

###############################################################################
# Tray-Only AppIndicator
###############################################################################

APPINDICATOR_ID = "ollama_bridge_indicator"
CHECK_INTERVAL_SEC = 5

class OllamaBridgeIndicator:
    def __init__(self):
        # Create AppIndicator
        self.indicator = AppIndicator3.Indicator.new(
            APPINDICATOR_ID,
            "",
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        
        # Create icons
        self.red_x_icon_path = self.generate_red_icon_with_black_x()
        self.green_icon_path = self.generate_green_icon()
        
        # Set initial icon & text
        self.update_icon(is_socat_active_on_11434())
        
        # Build menu
        self.indicator.set_menu(self.build_menu())
        
        # Periodically check bridging
        GLib.timeout_add_seconds(CHECK_INTERVAL_SEC, self.periodic_check)

    def build_menu(self):
        menu = Gtk.Menu()
        if is_socat_active_on_11434():
            disable_item = Gtk.MenuItem(label="Disable Ollama Bridge")
            disable_item.connect("activate", self.on_disable_bridge)
            menu.append(disable_item)
        else:
            enable_item = Gtk.MenuItem(label="Enable Ollama Bridge")
            enable_item.connect("activate", self.on_enable_bridge)
            menu.append(enable_item)
        
        sep = Gtk.SeparatorMenuItem()
        menu.append(sep)
        
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", self.on_quit)
        menu.append(quit_item)
        
        menu.show_all()
        return menu

    def refresh_menu(self):
        self.indicator.set_menu(self.build_menu())

    def on_enable_bridge(self, _):
        enable_bridge()
        self.update_icon(is_socat_active_on_11434())
        self.refresh_menu()

    def on_disable_bridge(self, _):
        disable_bridge()
        self.update_icon(is_socat_active_on_11434())
        self.refresh_menu()

    def update_icon(self, active):
        """Update icon color and set label/title to show bridged IPs."""
        if active:
            self.indicator.set_icon_full(self.green_icon_path, "BridgeActive")
            ips = get_private_ips()
            if ips:
                # e.g. "10.0.2.239 => 127.0.0.1:11434"
                ip_list_str = ",".join(ips)
                label_text = f"{ip_list_str} => 127.0.0.1:11434"
            else:
                label_text = "No private IPs found"
            
            # Attempt both label and title for maximum compatibility
            # (some desktops only show label, some only show title)
            self.indicator.set_title(label_text)
            try:
                # set_label(text, guide) -> text is displayed, guide is for accessibility
                self.indicator.set_label(label_text, "OllamaBridge")
            except TypeError:
                # Some older versions of AppIndicator might require only 1 arg
                self.indicator.set_label(label_text)
        else:
            self.indicator.set_icon_full(self.red_x_icon_path, "BridgeInactive")
            self.indicator.set_title("Disabled")
            try:
                self.indicator.set_label("Disabled", "OllamaBridge")
            except TypeError:
                self.indicator.set_label("Bridge Disabled")

    def generate_green_icon(self):
        img = Image.new("RGBA", (16, 16), (0, 255, 0, 255))
        tmp_path = "/tmp/ollama_bridge_green.png"
        img.save(tmp_path)
        return tmp_path

    def generate_red_icon_with_black_x(self):
        img = Image.new("RGBA", (16, 16), (255, 0, 0, 255))
        draw = ImageDraw.Draw(img)
        draw.line((0, 0, 15, 15), fill=(0, 0, 0, 255), width=3)
        draw.line((15, 0, 0, 15), fill=(0, 0, 0, 255), width=3)
        tmp_path = "/tmp/ollama_bridge_red_x.png"
        img.save(tmp_path)
        return tmp_path

    def periodic_check(self):
        self.update_icon(is_socat_active_on_11434())
        return True  # keep repeating

    def on_quit(self, _):
        Gtk.main_quit()

def main():
    # We no longer check for headless—this always attempts tray mode
    # Make sure $DISPLAY is set, or it won't work.
    if not os.getenv("DISPLAY"):
        print("ERROR: $DISPLAY is not set. Tray requires a GUI session.")
        sys.exit(1)

    # Launch tray
    OllamaBridgeIndicator()
    Gtk.main()

if __name__ == "__main__":
    main()

