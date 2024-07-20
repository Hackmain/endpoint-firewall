import argparse
import time
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS
from collections import defaultdict
from datetime import datetime, timedelta

# Define initial firewall rules and thresholds
ALLOWED_IPS = ["192.168.1.10", "10.0.0.5"]
BLOCKED_IPS = ["203.0.113.1", "198.51.100.2"]
ALLOWED_PORTS = [80, 443]
BLOCKED_PORTS = [22]

# DDoS and MITM attack thresholds
RATE_LIMIT_THRESHOLD = 100  # Maximum packets per minute from a single IP
RATE_LIMIT_WINDOW = timedelta(minutes=1)
PACKET_COUNT = defaultdict(int)
LAST_SEEN = defaultdict(datetime)

# To detect MITM attacks (e.g., ARP spoofing)
ARP_TABLE = {}
ARP_SPOOF_DETECTED = False

def packet_filter(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_info = f"Packet: {ip_src} -> {ip_dst}"

        # Rate Limiting for DDoS Protection
        now = datetime.now()
        if ip_src not in LAST_SEEN or (now - LAST_SEEN[ip_src]) > RATE_LIMIT_WINDOW:
            PACKET_COUNT[ip_src] = 0
        PACKET_COUNT[ip_src] += 1
        LAST_SEEN[ip_src] = now

        if PACKET_COUNT[ip_src] > RATE_LIMIT_THRESHOLD:
            print(f"DDoS Protection: Blocking IP {ip_src} due to rate limit exceedance")
            BLOCKED_IPS.append(ip_src)
            return

        # MITM Detection: ARP Spoofing
        if ARP in packet:
            arp_src_ip = packet[ARP].psrc
            arp_src_mac = packet[ARP].hwsrc
            arp_dst_ip = packet[ARP].pdst
            if arp_src_ip in ARP_TABLE and ARP_TABLE[arp_src_ip] != arp_src_mac:
                print(f"MITM Attack Detected: ARP Spoofing from IP {arp_src_ip} with MAC {arp_src_mac}")
                global ARP_SPOOF_DETECTED
                ARP_SPOOF_DETECTED = True
            ARP_TABLE[arp_src_ip] = arp_src_mac

        # Check if the packet should be allowed or blocked
        if ip_src in BLOCKED_IPS or ip_dst in BLOCKED_IPS:
            print(f"Blocked packet {packet_info}")
            return

        if ip_src in ALLOWED_IPS or ip_dst in ALLOWED_IPS:
            if packet[TCP].sport if TCP in packet else packet[UDP].sport in BLOCKED_PORTS or \
               packet[TCP].dport if TCP in packet else packet[UDP].dport in BLOCKED_PORTS:
                print(f"Blocked packet {packet_info}")
                return

            if packet[TCP].sport if TCP in packet else packet[UDP].sport in ALLOWED_PORTS or \
               packet[TCP].dport if TCP in packet else packet[UDP].dport in ALLOWED_PORTS:
                print(f"Allowed packet {packet_info}")

    # Check for MITM attacks (e.g., DNS spoofing)
    if DNS in packet and ARP_SPOOF_DETECTED:
        dns_src_ip = packet[DNS].qd.qname
        dns_src_mac = packet[DNS].src if TCP in packet else packet[UDP].src
        if dns_src_ip in ARP_TABLE and ARP_TABLE[dns_src_ip] != dns_src_mac:
            print(f"MITM Attack Detected: DNS Spoofing from IP {dns_src_ip} with MAC {dns_src_mac}")
            ARP_SPOOF_DETECTED = False

def packet_callback(packet):
    try:
        print(f"Received packet: {packet.summary()}")
        if ARP_SPOOF_DETECTED:
            print("MITM Attack Detected: ARP Spoofing")
        packet_filter(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")

def sniff_packets(interface):
    print(f"Sniffing packets on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

def show_logs():
    # Placeholder function for log viewing
    print("Displaying sniffed packet logs:")
    # Implement log viewing logic here
    pass

def modify_lists(action, ip=None, port=None, list_type=None):
    global ALLOWED_IPS, BLOCKED_IPS, ALLOWED_PORTS, BLOCKED_PORTS

    if list_type == "ip":
        if action == "add":
            if ip not in ALLOWED_IPS and ip not in BLOCKED_IPS:
                ALLOWED_IPS.append(ip)
            elif ip in BLOCKED_IPS:
                BLOCKED_IPS.remove(ip)
                ALLOWED_IPS.append(ip)
        elif action == "block":
            if ip in ALLOWED_IPS:
                ALLOWED_IPS.remove(ip)
            if ip not in BLOCKED_IPS:
                BLOCKED_IPS.append(ip)
    elif list_type == "port":
        if action == "add":
            if port not in ALLOWED_PORTS and port not in BLOCKED_PORTS:
                ALLOWED_PORTS.append(port)
            elif port in BLOCKED_PORTS:
                BLOCKED_PORTS.remove(port)
                ALLOWED_PORTS.append(port)
        elif action == "block":
            if port in ALLOWED_PORTS:
                ALLOWED_PORTS.remove(port)
            if port not in BLOCKED_PORTS:
                BLOCKED_PORTS.append(port)

def display_rules():
    print("Current Firewall Rules:")
    print("Allowed IPs:", ALLOWED_IPS)
    print("Blocked IPs:", BLOCKED_IPS)
    print("Allowed Ports:", ALLOWED_PORTS)
    print("Blocked Ports:", BLOCKED_PORTS)
    print("follow me in instagram esefkh740_")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Python Firewall")
    parser.add_argument('-sniff', action='store_true', help="Sniff network packets and log them")
    parser.add_argument('-interface', type=str, default='eth0', help="Network interface to sniff packets on")
    parser.add_argument('-logs', action='store_true', help="Show logs of sniffed packets")
    parser.add_argument('-add_ip', type=str, help="Add IP to allowed list")
    parser.add_argument('-block_ip', type=str, help="Block IP to blocked list")
    parser.add_argument('-add_port', type=int, help="Add port to allowed list")
    parser.add_argument('-block_port', type=int, help="Block port to blocked list")

    args = parser.parse_args()

    if args.sniff:
        sniff_packets(interface=args.interface)
    elif args.logs:
        show_logs()
    elif args.add_ip:
        modify_lists("add", ip=args.add_ip, list_type="ip")
        display_rules()
    elif args.block_ip:
        modify_lists("block", ip=args.block_ip, list_type="ip")
        display_rules()
    elif args.add_port:
        modify_lists("add", port=args.add_port, list_type="port")
        display_rules()
    elif args.block_port:
        modify_lists("block", port=args.block_port, list_type="port")
        display_rules()
    else:
        print("Please specify an option. Use -sniff to start sniffing packets, -logs to view logs, -add_ip to add IP, -block_ip to block IP, -add_port to add port, or -block_port to block port.")

if __name__ == "__main__":
    main()
    
    
