import os
import sys
import subprocess
import re
import csv
import threading
from pathlib import Path

# Try to ensure 'requests' is available (for DB update)
try:
    import requests
except Exception:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
        import requests  # type: ignore
    except Exception:
        requests = None  # We will handle lack of requests gracefully

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
CACHE_DIR = os.path.join(Path.home(), ".oui_lookup")
CACHE_FILE = os.path.join(CACHE_DIR, "manuf")

# ---------------------------------------------------------------------------
# Utility: MAC normalization / formatting
# ---------------------------------------------------------------------------

def norm_hex(mac: str) -> str:
    """Return MAC as 12 uppercase hex characters (no separators) or '' if invalid."""
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexchars) < 6:
        return ""
    return hexchars.upper()


def mac_to_format(mac: str, fmt: str) -> str:
    """
    Convert a MAC into one of:
      - 'As seen'        -> original mac
      - 'AA:BB:CC:DD:EE:FF'
      - 'AAAA.BBBB.CCCC'
    """
    if fmt == "As seen":
        return mac
    n = norm_hex(mac)
    if len(n) != 12:
        return mac

    if fmt == "AA:BB:CC:DD:EE:FF":
        return ":".join(n[i:i+2] for i in range(0, 12, 2))
    if fmt == "AAAA.BBBB.CCCC":
        return ".".join(n[i:i+4] for i in range(0, 12, 4))

    return mac


# ---------------------------------------------------------------------------
# Vendor DB: loading & lookup (Wireshark manuf format)
# ---------------------------------------------------------------------------

def _load_lines_from(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def fetch_manuf():
    """Download manuf file into CACHE_FILE (offline-friendly, never raises to caller)."""
    if requests is None:
        raise RuntimeError("Python 'requests' module is not available.")

    os.makedirs(CACHE_DIR, exist_ok=True)
    r = requests.get(MANUF_URL, timeout=15)
    r.raise_for_status()
    with open(CACHE_FILE, "wb") as f:
        f.write(r.content)


def load_manuf():
    """
    Load Wireshark manuf database.
    Returns (buckets, masks):
      buckets: dict[int, dict[prefix_hex -> vendor]]
      masks:   sorted list of hex-lengths (largest first)
    """
    lines = None

    # 1) Try cached file
    if os.path.isfile(CACHE_FILE):
        try:
            lines = _load_lines_from(CACHE_FILE)
        except Exception:
            lines = None

    # 2) Try bundled manuf next to script (if present)
    if lines is None:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        bundled = os.path.join(exe_dir, "manuf")
        if os.path.isfile(bundled):
            try:
                lines = _load_lines_from(bundled)
                # Also copy to cache for next time
                os.makedirs(CACHE_DIR, exist_ok=True)
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines)
            except Exception:
                lines = None

    # 3) Fallback: no manuf available → empty DB
    if lines is None:
        return {}, []

    buckets = {}  # key: hex_prefix_len, value: {prefix_hex -> vendor}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Format examples:
        #   00:00:00          XEROX CORPORATION
        #   00:50:C2/24       IEEE Registration Authority
        #   00-90-4C          Cisco Systems, Inc
        parts = line.split()
        if not parts:
            continue

        prefix = parts[0]
        vendor = " ".join(parts[1:]) if len(parts) > 1 else ""

        # Extract mask bits (if present)
        if "/" in prefix:
            base, mask_str = prefix.split("/", 1)
            try:
                mask_bits = int(mask_str)
            except ValueError:
                mask_bits = 24
        else:
            base = prefix
            # Assume 24 bits for classic OUI if only 3 bytes; else scale
            hexchars = re.sub(r"[^0-9A-Fa-f]", "", base)
            mask_bits = len(hexchars) * 4

        base_hex = norm_hex(base)
        if not base_hex:
            continue

        # Number of hex chars to match according to mask_bits
        hex_len = mask_bits // 4
        base_hex = base_hex[:hex_len]

        if hex_len not in buckets:
            buckets[hex_len] = {}
        # Do not overwrite an existing vendor if same prefix appears again
        if base_hex not in buckets[hex_len]:
            buckets[hex_len][base_hex] = vendor

    masks = sorted(buckets.keys(), reverse=True)
    return buckets, masks


def lookup_vendor(mac: str, buckets, masks):
    """
    mac: original MAC string
    buckets, masks: from load_manuf()
    """
    if not buckets or not masks:
        return ""
    n = norm_hex(mac)
    if len(n) < 6:
        return ""
    for hex_len in masks:
        if len(n) < hex_len:
            continue
        prefix = n[:hex_len]
        vendor = buckets[hex_len].get(prefix)
        if vendor:
            return vendor
    return ""


# ---------------------------------------------------------------------------
# Parsing Cisco outputs
# ---------------------------------------------------------------------------

MAC_RE = re.compile(
    r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{12}"
    r"|(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2})"
)

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_ios_mac_table(text: str):
    """
    Parse 'show mac address-table' output.
    Returns list of (vlan, mac, type, iface).
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip header lines
        if line.lower().startswith("vlan") or "mac address" in line.lower():
            continue

        m = MAC_RE.search(line)
        if not m:
            continue

        mac = m.group(1)
        parts = line.split()

        vlan = ""
        typ = ""
        iface = ""

        # Heuristic: VLAN often first, interface last
        if len(parts) >= 3:
            vlan = parts[0]
            iface = parts[-1]
            # Somewhere in the middle there is TYPE (DYNAMIC/STATIC)
            for p in parts[1:-1]:
                if p.isalpha():
                    typ = p
                    break

        entries.append((vlan, mac, typ, iface))

    return entries


def parse_ios_arp_table(text: str):
    """
    Parse Cisco IOS/IOS-XE 'show ip arp', 'show ip arp vrf X', or 'show arp' output.
    Returns list of (ip, mac, iface).
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Skip obvious header lines
        if line.lower().startswith("protocol") or line.lower().startswith("address"):
            continue
        if "Incomplete" in line:
            continue

        m_ip = IPV4_RE.search(line)
        m_mac = MAC_RE.search(line)
        if not m_ip or not m_mac:
            continue

        ip = m_ip.group(1)
        mac = m_mac.group(1)
        parts = line.split()
        iface = parts[-1] if parts else ""

        entries.append((ip, mac, iface))

    return entries


def detect_hostname(text: str):
    """
    Try to detect hostname from CLI prompt lines:
    e.g. "Switch01# show mac address-table"
         "RTR01(config)# do show ip arp"
    """
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Match 'NAME#' or 'NAME>' at start of line
        m = re.match(r"^([A-Za-z0-9._\-]+)\s*(?:[#>])", line)
        if m:
            return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def iface_sort_key(iface: str):
    """
    Simple sort key for interfaces (Gi1/0/1, Te1/1/1, Po1, etc.).
    Not perfect but better than pure string sort.
    """
    if not iface:
        return (999, 999, 999, iface)

    # Detect port-channel specially
    if iface.startswith("Po"):
        try:
            idx = int(re.sub(r"\D", "", iface) or "0")
        except ValueError:
            idx = 999
        return (3, idx, 0, iface)

    # Try to split like Gi1/0/1 -> (Gi, 1, 0, 1)
    m = re.match(r"([A-Za-z]+)(\d+)(?:/(\d+))?(?:/(\d+))?", iface)
    if not m:
        return (2, 999, 999, iface)

    nums = [int(x) if x is not None else 0 for x in m.groups()[1:]]
    return (1, *nums, iface)


def correlate_mac_and_arp(
    switch_inputs,
    router_inputs,
    buckets,
    masks,
    mac_fmt="AA:BB:CC:DD:EE:FF",
    exclude_po=True,
    exclude_cpu=False,
):
    """
    switch_inputs: list of dicts: { "name": str, "text": str }
    router_inputs: list of dicts: { "name": str, "text": str }
    Returns list of rows:
      (switch_name, vlan, sw_iface, mac_fmt_out, vendor, ip, router_name, arp_iface)
    """
    # 1. Build ARP index across all routers
    arp_index = {}  # key: normalized MAC (12 hex), value: list of dicts

    for r in router_inputs:
        raw = (r.get("text") or "").strip()
        if not raw:
            continue
        router_name = (r.get("name") or "").strip()
        if not router_name:
            auto = detect_hostname(raw)
            if auto:
                router_name = auto

        arp_rows = parse_ios_arp_table(raw)
        for ip, mac, iface in arp_rows:
            key = norm_hex(mac)
            if len(key) != 12:
                continue
            arp_index.setdefault(key, []).append({
                "ip": ip,
                "router": router_name,
                "iface": iface,
            })

    # 2. Walk all switch MAC tables and correlate
    results = []

    for s in switch_inputs:
        raw = (s.get("text") or "").strip()
        if not raw:
            continue
        sw_name = (s.get("name") or "").strip()
        if not sw_name:
            auto = detect_hostname(raw)
            if auto:
                sw_name = auto

        mac_rows = parse_ios_mac_table(raw)
        for vlan, mac, typ, iface in mac_rows:
            # Filters
            if exclude_po and iface.startswith("Po"):
                continue
            if exclude_cpu and iface.upper() == "CPU":
                continue

            norm = norm_hex(mac)
            vendor = lookup_vendor(mac, buckets, masks)
            mac_out = mac_to_format(mac, mac_fmt) if mac_fmt != "As seen" else mac

            matches = arp_index.get(norm)

            if not matches:
                # No ARP match at all → still keep the MAC
                results.append((
                    sw_name, vlan, iface, mac_out, vendor,
                    "", "", ""   # ip, router_name, arp_iface
                ))
            else:
                # Possibly multiple IPs and/or routers for the same MAC
                for m in matches:
                    results.append((
                        sw_name, vlan, iface, mac_out, vendor,
                        m["ip"], m["router"], m["iface"]
                    ))

    return results


# ---------------------------------------------------------------------------
# GUI application
# ---------------------------------------------------------------------------

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Cisco MAC OUI Resolver (Multi-Device)")

        # Load vendor DB (offline-tolerant)
        try:
            self.buckets, self.masks = load_manuf()
        except Exception:
            self.buckets, self.masks = {}, []

        self.last_rows = []

        main = ttk.Frame(root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        # Top options row
        opt_row = ttk.Frame(main)
        opt_row.pack(fill="x", pady=(0, 6))

        ttk.Label(opt_row, text="MAC Format:").pack(side="left")
        self.mac_fmt = tk.StringVar(value="AA:BB:CC:DD:EE:FF")
        fmt_box = ttk.Combobox(
            opt_row,
            textvariable=self.mac_fmt,
            values=["As seen", "AA:BB:CC:DD:EE:FF", "AAAA.BBBB.CCCC"],
            state="readonly",
            width=20,
        )
        fmt_box.pack(side="left", padx=(4, 12))

        self.exclude_po = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt_row,
            text="Exclude Port-Channels (Po*)",
            variable=self.exclude_po
        ).pack(side="left")

        # New toggles
        self.exclude_cpu = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt_row,
            text="Exclude CPU MACs",
            variable=self.exclude_cpu
        ).pack(side="left", padx=(8, 0))

        self.only_ip = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opt_row,
            text="Only rows with IP match",
            variable=self.only_ip
        ).pack(side="left", padx=(8, 0))

        ttk.Label(opt_row, text=" ").pack(side="left", padx=4)  # spacer

        ttk.Button(opt_row, text="Lookup", command=self.lookup).pack(side="left", padx=(4, 2))
        ttk.Button(opt_row, text="Export CSV", command=self.export_csv).pack(side="left", padx=2)
        ttk.Button(opt_row, text="Update DB", command=self.update_db).pack(side="left", padx=2)
        ttk.Button(opt_row, text="Load DB File", command=self.load_db_file).pack(side="left", padx=2)
        ttk.Button(opt_row, text="Clear All", command=self.clear_all).pack(side="left", padx=(12, 0))

        # Notebook with 5 switch + 2 router tabs
        nb = ttk.Notebook(main)
        nb.pack(fill="both", expand=True, pady=(4, 6))

        self.switch_blocks = []
        self.router_blocks = []

        for i in range(1, 6):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"SW{i}")
            block = self._build_device_tab(frame, is_router=False, index=i)
            self.switch_blocks.append(block)

        for i in range(1, 3):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"RT{i}-ARP")
            block = self._build_device_tab(frame, is_router=True, index=i)
            self.router_blocks.append(block)

        # Result table
        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill="both", expand=True)

        columns = ("switch", "vlan", "iface", "mac", "vendor", "ip", "router", "arp_iface")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.heading("switch", text="Switch")
        self.tree.heading("vlan", text="VLAN")
        self.tree.heading("iface", text="Interface")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("ip", text="IP")
        self.tree.heading("router", text="Router")
        self.tree.heading("arp_iface", text="ARP Interface")

        self.tree.column("switch", width=140, anchor="w")
        self.tree.column("vlan", width=60, anchor="center")
        self.tree.column("iface", width=120, anchor="w")
        self.tree.column("mac", width=160, anchor="w")
        self.tree.column("vendor", width=260, anchor="w")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("router", width=140, anchor="w")
        self.tree.column("arp_iface", width=120, anchor="w")

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(main, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", pady=(4, 0))

    # ------------------------------------------------------------------
    # Tab builder
    # ------------------------------------------------------------------

    def _build_device_tab(self, frame, is_router: bool, index: int):
        """
        Build one device tab: either switch or router.
        Returns dict with "host_var" and "txt".
        """
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=(4, 4))

        ttk.Label(top, text="Hostname:").pack(side="left")
        host_var = tk.StringVar()
        ttk.Entry(top, textvariable=host_var, width=24).pack(side="left", padx=(4, 8))

        paste_btn = ttk.Button(
            top,
            text="Paste",
            command=lambda v=host_var, f=frame: self._paste_into_tab(f, v)
        )
        paste_btn.pack(side="left", padx=2)

        load_btn = ttk.Button(
            top,
            text="Load File",
            command=lambda f=frame: self._load_file_into_tab(f)
        )
        load_btn.pack(side="left", padx=2)

        hint_text = "Paste 'show mac address-table' output"
        if is_router:
            hint_text = "Paste 'show ip arp' (or 'show ip arp vrf ...') output"

        ttk.Label(top, text=hint_text).pack(side="left", padx=(10, 0))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True)

        txt = tk.Text(text_frame, wrap="none", height=12)
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=txt.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        txt.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        return {"frame": frame, "host_var": host_var, "txt": txt}

    # ------------------------------------------------------------------
    # Helpers for tabs
    # ------------------------------------------------------------------

    def _find_block_by_frame(self, frame):
        for b in self.switch_blocks + self.router_blocks:
            if b["frame"] is frame:
                return b
        return None

    def _paste_into_tab(self, frame, host_var):
        block = self._find_block_by_frame(frame)
        if not block:
            return
        try:
            clip = self.root.clipboard_get()
        except Exception:
            clip = ""
        if not clip:
            return
        txt = block["txt"]
        txt.delete("1.0", "end")
        txt.insert("1.0", clip)

        # If hostname is empty, try to detect it automatically
        if not host_var.get().strip():
            auto = detect_hostname(clip)
            if auto:
                host_var.set(auto)

    def _load_file_into_tab(self, frame):
        block = self._find_block_by_frame(frame)
        if not block:
            return
        p = filedialog.askopenfilename(
            title="Select text file",
            filetypes=[("Text files", "*.txt *.log *.out *.cfg"), ("All files", "*.*")]
        )
        if not p:
            return
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return

        txt = block["txt"]
        txt.delete("1.0", "end")
        txt.insert("1.0", content)

        # Try to detect hostname from content for convenience
        host_var = block["host_var"]
        if not host_var.get().strip():
            auto = detect_hostname(content)
            if auto:
                host_var.set(auto)

    # ------------------------------------------------------------------
    # Status handling
    # ------------------------------------------------------------------

    def set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------

    def lookup(self):
        """Correlate MAC tables with ARP tables across all devices."""
        # Clear previous display
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.last_rows = []

        # Collect inputs
        switch_inputs = []
        for b in self.switch_blocks:
            txt = b["txt"].get("1.0", "end")
            name = b["host_var"].get().strip()
            switch_inputs.append({"name": name, "text": txt})

        router_inputs = []
        for b in self.router_blocks:
            txt = b["txt"].get("1.0", "end")
            name = b["host_var"].get().strip()
            router_inputs.append({"name": name, "text": txt})

        mac_fmt = self.mac_fmt.get()
        exclude_po = self.exclude_po.get()
        exclude_cpu = self.exclude_cpu.get()
        only_ip = self.only_ip.get()

        self.set_status("Resolving MACs and correlating with ARP...")

        def run():
            try:
                rows = correlate_mac_and_arp(
                    switch_inputs,
                    router_inputs,
                    self.buckets,
                    self.masks,
                    mac_fmt=mac_fmt,
                    exclude_po=exclude_po,
                    exclude_cpu=exclude_cpu,
                )

                # Optional filter: only rows with IP match
                if only_ip:
                    rows = [r for r in rows if str(r[5]).strip()]

                # Sort results for display (Switch, VLAN, Interface)
                def sort_key(r):
                    sw, vlan, iface = r[0], r[1], r[2]
                    try:
                        vlan_num = int(vlan)
                    except Exception:
                        vlan_num = 9999
                    return (sw or "", vlan_num, iface_sort_key(iface or ""))

                rows.sort(key=sort_key)

                self.root.after(0, self._populate_tree, rows)
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Error: {e}"))

        threading.Thread(target=run, daemon=True).start()

    def _populate_tree(self, rows):
        self.last_rows = rows
        for r in rows:
            self.tree.insert("", "end", values=r)
        self.set_status(f"{len(rows)} row(s) displayed")

    def export_csv(self):
        """Export current table to a CSV file, sorted by Hostname then Interface."""
        if not self.last_rows:
            messagebox.showinfo("Export CSV", "No data to export.")
            return

        # Sort by Switch (hostname), then Interface numerically
        rows = sorted(
            self.last_rows,
            key=lambda r: ((r[0] or ""), iface_sort_key(r[2] or ""))
        )

        p = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Switch", "VLAN", "Interface", "MAC", "Vendor",
                            "IP", "Router", "ARP_Interface"])
                for r in rows:
                    w.writerow(r)
            self.set_status(f"Exported {len(rows)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

    def clear_all(self):
        """Clear all text inputs and table."""
        for b in self.switch_blocks + self.router_blocks:
            b["txt"].delete("1.0", "end")
            b["host_var"].set("")
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.last_rows = []
        self.set_status("Cleared")

    # ------------------------------------------------------------------
    # Vendor DB actions
    # ------------------------------------------------------------------

    def update_db(self):
        """Download latest Wireshark manuf file and reload DB."""
        def run():
            try:
                self.set_status("Updating vendor DB from Wireshark...")
                if requests is None:
                    raise RuntimeError("Python 'requests' module is not available.")
                fetch_manuf()
                self.buckets, self.masks = load_manuf()
                self.set_status("Vendor DB updated")
            except Exception as e:
                self.set_status("Vendor DB update failed")
                messagebox.showerror("Error", f"Vendor DB update failed:\n{e}")

        threading.Thread(target=run, daemon=True).start()

    def load_db_file(self):
        """Load a local manuf file into the cache and reload DB."""
        p = filedialog.askopenfilename(
            title="Select manuf file",
            filetypes=[("manuf or text", "*.*")]
        )
        if not p:
            return
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(p, "rb") as src, open(CACHE_FILE, "wb") as dst:
                dst.write(src.read())
            self.buckets, self.masks = load_manuf()
            self.set_status(f"Loaded vendor DB from {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load manuf file:\n{e}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    app = App(root)
    root.geometry("1200x800")
    root.mainloop()


if __name__ == "__main__":
    main()
