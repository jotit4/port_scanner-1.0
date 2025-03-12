import os
import sys
import subprocess

# Clear console before execution
os.system('clear' if os.name == 'posix' else 'cls')

try:
    import nmap
except ImportError:
    print("[!] Missing dependency: python-nmap\n[+] Install it using: pip install python-nmap")
    sys.exit(1)

try:
    import socket
except ImportError:
    print("[!] Missing dependency: socket (should be built-in)")
    sys.exit(1)

try:
    from scapy.all import sr, IP, TCP
except ImportError:
    print("[!] Missing dependency: scapy\n[+] Install it using: pip install scapy")
    sys.exit(1)

def show_anonymity_warning():
    warning = """
###############################################
#  ⚠ WARNING: Stay Anonymous!                #
#                                             #
#  Consider using Tor or ProxyChains before  #
#  running this scan to enhance anonymity.   #
#                                             #
#  Example:                                   #
#  $ sudo proxychains python3 scanner.py     #
###############################################
\n
\n
## Consider executing this script as root, otherwise it may not work properly ##
    """
    print(warning)

def show_tor_instructions():
    instructions = """
=== How to Stay Anonymous ===

1. Install Tor and ProxyChains:
   $ sudo apt install tor proxychains

2. Start the Tor service:
   $ sudo systemctl start tor

3. Configure ProxyChains:
   Edit /etc/proxychains.conf and ensure the last line is:
   socks5  127.0.0.1 9050

4. Run this script with ProxyChains:
   $ sudo proxychains python3 scanner.py

========================================
    """
    print(instructions)

def scan_with_nmap(target, scan_type):
    os.system('clear' if os.name == 'posix' else 'cls')
    nm = nmap.PortScanner()
    print(f"[+] Scanning {target} with Nmap...")
    arguments = "-sS -p 1-65535 --open" if scan_type == "1" else "-sV -p 1-65535 --open"
    nm.scan(hosts=target, arguments=arguments)
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port {port}: {nm[host][proto][port]['state']}")

def scan_with_socket(target):
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"[+] Scanning {target} with Socket...")
    for port in range(1, 65535):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} is open")

def scan_with_scapy(target):
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"[+] Scanning {target} with Scapy...")
    ports = range(1, 65535)
    ans, _ = sr(IP(dst=target)/TCP(dport=ports, flags="S"), timeout=1, verbose=False)
    for sent, received in ans:
        if received.haslayer(TCP) and received[TCP].flags == 0x12:
            print(f"Port {sent[TCP].dport} is open")

def main():
    show_anonymity_warning()
    while True:
        print("\n=== Port Scanner ===")
        print("1. Stealth Scan (Nmap -sS)")
        print("2. Detailed Scan (Nmap -sV)")
        print("3. Basic Scan (Socket)")
        print("4. Advanced Scan (Scapy)")
        print("5. View Instructions for Anonymity")
        print("6. Exit")
        choice = input("Select an option: ")

        os.system('clear' if os.name == 'posix' else 'cls')

        if choice in ["1", "2"]:
            target = input("Enter target IP: ")
            scan_with_nmap(target, choice)
        elif choice == "3":
            target = input("Enter target IP: ")
            scan_with_socket(target)
        elif choice == "4":
            target = input("Enter target IP: ")
            scan_with_scapy(target)
        elif choice == "5":
            show_tor_instructions()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
