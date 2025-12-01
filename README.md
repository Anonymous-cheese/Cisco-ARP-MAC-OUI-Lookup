# Cisco-ARP-MAC-OUI-Lookup

A Windows-friendly GUI tool for **multi-device MAC table parsing, ARP correlation, and OUI vendor identification**.  
Supports **5 Cisco switches** and **2 Cisco routers** simultaneously, with automatic hostname detection, offline/online vendor lookup, flexible MAC formatting, CSV export, and fast correlation of MAC → IP → Router.

Designed for real-world Cisco troubleshooting environments and validated using IOS/IOS-XE outputs.

---

##  Features

###  Multi-Device Parsing  
- Parse up to **5 switch MAC tables** (`show mac address-table`)  
- Parse up to **2 router ARP tables** (`show ip arp`, with or without VRF)

###  MAC ↔ ARP Correlation  
- Automatically correlate MAC entries from switches with ARP entries from routers  
- Displays:
  - Switch name  
  - VLAN  
  - Interface  
  - MAC (user-selected formatting)  
  - Vendor (OUI)  
  - IP address  
  - Router name  
  - ARP interface  

###  Intelligent Hostname Detection  
- Automatically reads device hostnames from CLI prompts in pasted text  
- Example supported prompts:  
  ```
  78-01-RT01#
  300-01-SW02#
  Switch01>
  ```

###  GUI-Based Workflow  
- Clean, simple Tkinter interface  
- Tabs for all 7 devices  
- Paste/output directly or load text files from SecureCRT, PuTTY, etc.

### Filters & Options  
- **MAC format selector:**  
  - As seen  
  - `AA:BB:CC:DD:EE:FF`  
  - `AAAA.BBBB.CCCC`  
- **Exclude Port-Channels (Po*)**  
- **Only show rows with ARP match**  
- **Exclude CPU MACs**  
- All filters are optional and non-destructive

###  CSV Export  
- One-click CSV export  
- Sorted by:
  1. **Hostname alphabetically**
  2. **Interface in natural numeric order** (`Gi1/0/1`, `Gi1/0/2`, `Gi1/0/10`, etc.)

###  Offline + Online OUI Lookup  
- Offline lookup using Wireshark’s `manuf` database  
- Automatic online pull when needed  
- Caches results locally (`manuf_local.txt`)

---

##  How to Use

### 1. Paste or Load Device Outputs  
For each tab (`SW1`…`SW5`, `RT1-ARP`, `RT2-ARP`):

- Paste output from:
  ```
  show mac address-table
  show ip arp
  show ip arp vrf FVRF
  ```
- or click **Load File** to import saved text.

### 2. Adjust Options (Optional)  
- Choose your preferred MAC formatting  
- Enable/disable filters  
- Keep CPU MAC filtering and ARP-only filtering as needed

### 3. Click **Lookup**  
The results table populates with every MAC → IP correlation.

### 4. Export as CSV  
Click **Export CSV** to save your results.

---

##  Example Workflows

### ➤ Troubleshooting a client on a 3-switch stack and dual routers
1. Paste MAC table from all switches (`SW1–SW3`)  
2. Paste ARP from both routers (`RT1`, `RT2`)  
3. Click **Lookup** → instantly see which switch/port and which router/IP  
4. Export CSV for documentation

### ➤ Identifying rogue devices  
- Use **OUI lookup** for unknown MAC prefixes  
- Filter for **only IP-matched entries**  
- CPU MACs excluded to reduce noise

---

## 🛠️ Requirements

- Python 3.10+  
- Windows 10/11 recommended  
- No external dependencies beyond standard libraries  
- Optional: PyInstaller to build `.exe`

---

## 📜 License  
MIT License — feel free to use, modify, and contribute.
