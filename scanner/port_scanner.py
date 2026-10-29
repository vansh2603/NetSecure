import socket


def scan_port(target, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                return True
            else:
                return False

    except (socket.gaierror, socket.timeout, OSError):
        return False


def scan_ports(target, ports):
    open_ports = []

    for port in ports:
        if scan_port(target, port):
            open_ports.append(port)

    return open_ports


if __name__ == "__main__":

    target = "127.0.0.1"

    ports = [
        21, 22, 23, 25, 53,
        80, 110, 139, 143,
        443, 445, 3389, 8080
    ]

    print("=" * 40)
    print("          NETSECURE")
    print("=" * 40)
    print(f"Target: {target}")
    print()
    print("PORT        STATE")
    print("-" * 25)

    open_ports = scan_ports(target, ports)

    for port in open_ports:
        print(f"{port:<11} OPEN")

    print("-" * 25)
    print("Scan completed successfully.")
    print("=" * 40)