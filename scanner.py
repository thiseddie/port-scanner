
import socket
import argparse
import json
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

DEFAULT_TIMEOUT = 1
MAX_THREADS = 200

COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "SMB",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP TLS",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    27017: "MongoDB"
}


class PortScanner:
    def __init__(self, target, start_port, end_port, timeout, threads, banner):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.banner = banner
        self.results = []

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                banner = ""

                if self.banner:
                    banner = self.grab_banner(sock)

                data = {
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner.strip()
                }

                return data

        except socket.gaierror:
            pass

        except socket.timeout:
            pass

        except Exception:
            pass

        finally:
            sock.close()

        return None

    def grab_banner(self, sock):
        try:
            sock.sendall(b"HELLO\r\n")
            response = sock.recv(1024)
            return response.decode(errors="ignore")
        except Exception:
            return ""

    def start_scan(self):
        print(f"\n{Fore.CYAN}[*] Starting scan on {self.target}")
        print(f"{Fore.CYAN}[*] Port range: {self.start_port}-{self.end_port}")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        print(f"{Fore.CYAN}[*] Timeout: {self.timeout}s\n")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port, port): port
                for port in range(self.start_port, self.end_port + 1)
            }

            for future in as_completed(futures):
                result = future.result()

                if result:
                    self.results.append(result)

                    print(
                        f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                        f"Port {result['port']:5} | "
                        f"Service: {result['service']:15} | "
                        f"Banner: {result['banner'][:50]}"
                    )

        elapsed = round(time.time() - start_time, 2)

        print(f"\n{Fore.YELLOW}[+] Scan completed in {elapsed} seconds")
        print(f"{Fore.YELLOW}[+] Open ports found: {len(self.results)}\n")

    def save_results(self, filename):
        with open(filename, "w") as file:
            json.dump(self.results, file, indent=4)

        print(f"{Fore.BLUE}[+] Results saved to {filename}")



def validate_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False



def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Multithreaded TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-sp",
        "--start-port",
        type=int,
        default=1,
        help="Starting port (default: 1)"
    )

    parser.add_argument(
        "-ep",
        "--end-port",
        type=int,
        default=1024,
        help="Ending port (default: 1024)"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds"
    )

    parser.add_argument(
        "-th",
        "--threads",
        type=int,
        default=MAX_THREADS,
        help="Number of threads"
    )

    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Enable banner grabbing"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save output to JSON file"
    )

    return parser.parse_args()



def main():
    args = parse_arguments()

    if not validate_target(args.target):
        print(f"{Fore.RED}[-] Invalid target")
        return

    if args.start_port < 1 or args.end_port > 65535:
        print(f"{Fore.RED}[-] Port range must be between 1 and 65535")
        return

    if args.start_port > args.end_port:
        print(f"{Fore.RED}[-] Start port cannot be greater than end port")
        return

    scanner = PortScanner(
        target=args.target,
        start_port=args.start_port,
        end_port=args.end_port,
        timeout=args.timeout,
        threads=args.threads,
        banner=args.banner
    )

    scanner.start_scan()

    if args.output:
        scanner.save_results(args.output)


if __name__ == "__main__":
    main()


