import socket
from ftplib import FTP

def port_scanner(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306]

    print(f"\n[+] Scanning {target} for open ports...")
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port} is open.")
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"[ERROR] Could not scan port {port}: {e}")

    if not open_ports:
        print("[*] No open ports found.")
    return open_ports

def brute_force_ftp(host, user, password_list):
    print(f"\n[+] Starting FTP brute-force on {host} as user '{user}'")
    for password in password_list:
        try:
            ftp = FTP(host)
            ftp.login(user, password)
            print(f"[SUCCESS] Login successful: {user}:{password}")
            ftp.quit()
            return password
        except Exception:
            print(f"[-] Failed login: {user}:{password}")
    print("[*] Brute-force failed. No valid password found.")
    return None

def main():
    print("=== Penetration Testing Toolkit ===")
    target = input("Enter target IP or domain: ").strip()

    print("\n[1] Port Scan\n[2] Brute Force FTP")
    choice = input("Select a module (1 or 2): ").strip()

    if choice == '1':
        ports = input("Enter ports to scan (comma-separated) or press Enter for default: ").strip()
        ports = [int(p.strip()) for p in ports.split(",")] if ports else None
        port_scanner(target, ports)
    elif choice == '2':
        user = input("Enter FTP username: ").strip()
        password_list = ['admin', '1234', 'password', 'ftp', 'letmein', 'password123']
        brute_force_ftp(target, user, password_list)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()