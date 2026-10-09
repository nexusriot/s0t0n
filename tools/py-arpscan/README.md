# py-arpscan

ARP broadcast **sweep** of a CIDR via scapy (Python). Sends a single ARP
request to the range and prints responding IP/MAC pairs.

> Needs root and `scapy`. Authorized use only.

## Usage

```bash
pip install scapy
sudo python3 arpscan.py 192.168.1.0/24
```
