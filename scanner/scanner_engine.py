
from scanner.port_scanner import scan_ports


def run_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5000, 8000, 8080]

    open_ports = scan_ports(target, ports)

    results = []

    for port in ports:
        is_open = port in open_ports

        service_names = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5000: "Flask/Development",
            5432: "PostgreSQL",
            8000: "HTTP/Development",
            8080: "HTTP-Alternate"
        }

        results.append({
            "port": port,
            "state": "Open" if is_open else "Closed",
            "protocol": "TCP",
            "service": service_names.get(port, "Unknown")
        })

    return {
        "target": target,
        "total_ports_checked": len(ports),
        "open_ports": [r for r in results if r["state"] == "Open"],
        "results": results
    }


if __name__ == "__main__":
    report = run_scan("127.0.0.1")

    print("Target:", report["target"])
    print("Ports checked:", report["total_ports_checked"])
    print("Open ports:")

    for port in report["open_ports"]:
        print(port)
