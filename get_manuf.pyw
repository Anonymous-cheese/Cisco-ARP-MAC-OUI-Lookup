import os, sys, subprocess
try:
    import requests
except Exception:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

import tkinter as tk
from tkinter import messagebox

URL="https://www.wireshark.org/download/automated/data/manuf"

def verify_arg():
    p=os.environ.get("REQUESTS_CA_BUNDLE")
    if p and os.path.exists(p): return p
    local_ca=os.path.join(os.path.dirname(__file__),"corp_ca.pem")
    if os.path.exists(local_ca): return local_ca
    return True

def main():
    outdir=os.path.abspath(os.path.dirname(__file__))
    outpath=os.path.join(outdir,"manuf")
    try:
        r=requests.get(URL,timeout=30,verify=verify_arg())
        r.raise_for_status()
        with open(outpath,"wb") as f: f.write(r.content)
        root=tk.Tk(); root.withdraw()
        messagebox.showinfo("Done", f"Saved manuf to:\n{outpath}")
    except Exception as e:
        root=tk.Tk(); root.withdraw()
        messagebox.showerror("Error", str(e))

if __name__=="__main__":
    main()
