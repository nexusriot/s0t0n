from scapy.all import ARP, Ether, srp
import sys

def arp_scan(network_cidr):
    # Create Ethernet frame + ARP request
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
    
    print(f"Scanning {network_cidr}...\n")
    answered, _ = srp(packet, timeout=2, verbose=0)
    
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for sent, received in answered:
        print(f"{received.psrc:16}\t{received.hwsrc}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <CIDR>")
        print(f"Example: sudo python3 {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)
    
    arp_scan(sys.argv[1])

