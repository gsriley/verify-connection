import socket

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

def main():
    servers = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1"
    }

    for name, ip in servers.items():
        if check_connectivity(ip):
            print(f"[✅] {name} ({ip}) is reachable")
        else:
            print(f"[❌] {name} ({ip}) is NOT reachable")

if __name__ == "__main__":
    main()
