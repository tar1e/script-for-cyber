import socket
import concurrent.futures
import argparse

# Dictionary of common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

def scan_port(host, port, timeout=1):
    """Check if a port is open and try to grab a banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:  # Port is open
            try:
                sock.sendall(b"\r\n")  # Send a dummy request
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "Could not grab banner"
            finally:
                sock.close()
            
            service = COMMON_PORTS.get(port, "Unknown")
            return f"[+] {host}:{port} OPEN | Service: {service} | Banner: {banner}"
        sock.close()
    except:
        pass
    return None

def scan_host(host, ports, threads=100):
    """Scan multiple ports on a host using multithreading."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            res = future.result()
            if res:
                results.append(res)
    return results

def parse_ports(ports_str):
    """Parse port ranges (e.g. '22,80,443' or '1-1024')."""
    ports = set()
    for part in ports_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multithreaded port scanner")
    parser.add_argument("-H", "--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan (e.g. 1-1024 or 22,80,443)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads (default: 200)")

    args = parser.parse_args()

    target_host = args.host
    port_list = parse_ports(args.ports)

    print(f"Scanning {target_host} on ports: {args.ports}")
    results = scan_host(target_host, port_list, threads=args.threads)

    for r in sorted(results):
        print(r)
