#!/usr/bin/env python3
"""
ScreenConnect Target Hunter - NO API REQUIRED
Fast port scanning + web fingerprinting
"""

import socket
import ssl
import sys
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== CONFIG ====================
TIMEOUT = 3
MAX_THREADS = 100
PORTS = [443, 8040, 8041, 8080, 8443, 80]

# Common ScreenConnect hosting ranges (DigitalOcean, AWS, Linode, Vultr)
COMMON_RANGES = [
    "159.89", "159.203", "165.227", "167.99", "138.68", "188.166", "178.62",
    "104.131", "107.170", "128.199", "139.59", "146.185", "159.65", "161.35",
    "162.243", "164.90", "165.22", "167.172", "174.138", "178.128", "188.226",
    "192.241", "198.199", "206.189", "209.97", "46.101", "68.183", "95.179"
]

# ScreenConnect fingerprints
FINGERPRINTS = [
    "ScreenConnect", "ConnectWise", "Remote Support", 
    "Host Session", "ScreenConnect Client", "/Login", "/Admin"
]

# ==================== SCANNING FUNCTIONS ====================

def port_open(host, port):
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_screenconnect(host, port):
    """Check if ScreenConnect is running on host:port"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        protocol = "https" if port in [443, 8041, 8443] else "http"
        
        if protocol == "https":
            conn = context.wrap_socket(socket.socket(), server_hostname=host)
            conn.connect((host, port))
        else:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((host, port))
        
        # Send HTTP request
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        conn.send(request.encode())
        
        # Read response
        response = b""
        while True:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk
            except:
                break
        conn.close()
        
        # Decode and check
        response_text = response.decode('utf-8', errors='ignore')
        
        for fingerprint in FINGERPRINTS:
            if fingerprint.lower() in response_text.lower():
                return True
    except:
        pass
    return False

def scan_ip(ip):
    """Scan single IP for ScreenConnect"""
    results = []
    for port in PORTS:
        if port_open(ip, port):
            if check_screenconnect(ip, port):
                results.append(f"{ip}:{port}")
                print(f"[+] {ip}:{port}")
    return results

def generate_ips():
    """Generate IPs to scan from common ranges"""
    ips = []
    
    # Method 1: Common hosting ranges
    for prefix in COMMON_RANGES:
        for last_octet in range(1, 255):
            ips.append(f"{prefix}.{last_octet}")
            if len(ips) > 5000:
                break
        if len(ips) > 5000:
            break
    
    # Method 2: Add random public IPs
    random_ips = [
        f"1.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        for _ in range(2000)
    ]
    ips.extend(random_ips)
    
    return list(set(ips))

def scan_from_file(filename):
    """Scan IPs from a file (one per line)"""
    try:
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        return ips
    except:
        return []

# ==================== MAIN ====================

def main():
    print("""
╔═══════════════════════════════════════════════╗
║     ScreenConnect Target Hunter - NO API      ║
║     Fast | Free | Pure Python                 ║
╚═══════════════════════════════════════════════╝
    """)
    
    # Get targets
    targets = []
    
    # Option 1: Scan common ranges (fastest)
    print("[*] Option 1: Scan common hosting ranges (5,000+ IPs)")
    # Option 2: Scan from file
    print("[*] Option 2: Scan from file (create ips.txt)")
    
    choice = input("\n[?] Enter 1 (scan ranges) or 2 (scan file): ").strip()
    
    if choice == "2":
        filename = input("[?] Enter filename (e.g., ips.txt): ").strip()
        targets = scan_from_file(filename)
        print(f"[*] Loaded {len(targets)} IPs from file")
    else:
        print("[*] Generating IPs from common hosting ranges...")
        targets = generate_ips()
        print(f"[*] Generated {len(targets)} IPs to scan")
    
    print(f"[*] Scanning with {MAX_THREADS} threads...\n")
    
    found = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in targets}
        
        for i, future in enumerate(as_completed(futures)):
            results = future.result()
            found.extend(results)
            
            # Progress update every 500 IPs
            if (i + 1) % 500 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"[*] Progress: {i+1}/{len(targets)} | Found: {len(found)} | Rate: {rate:.0f} IPs/sec")
    
    # Save results
    with open("targets.txt", "w") as f:
        for target in found:
            f.write(f"{target}\n")
    
    elapsed = time.time() - start_time
    print(f"\n[✓] Scan complete!")
    print(f"[✓] Time: {elapsed:.1f} seconds")
    print(f"[✓] Found: {len(found)} ScreenConnect targets")
    print(f"[✓] Saved to: targets.txt")
    
    if found:
        print("\n[+] Sample targets:")
        for t in found[:10]:
            print(f"    https://{t}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        sys.exit(0)