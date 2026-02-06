import socket, struct, hashlib, time

TARGET_IP = '172.20.9.230' # Node B IP
TARGET_PORT = 18333
MAGIC = b'\x0b\x11\x09\x07' # Testnet3

def create_msg(cmd, payload):
    command = cmd.encode('ascii').ljust(12, b'\x00')
    length = struct.pack('<I', len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command + length + checksum + payload

def force_ban():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_IP, TARGET_PORT))
    
    # Standard version payload
    version_payload = struct.pack('<iQqQq26s26sQ16sI', 70015, 1, int(time.time()), 0, 0, b'', b'', 0, b'', 0)
    
    print("[1] Sending first version...")
    s.send(create_msg("version", version_payload))
    print(f"Total sent bytes: {len(create_msg('version', version_payload))}")
    
    time.sleep(1) # Wait for Node B to process
    
    print("[2] Sending SECOND version (Protocol Violation)...")
    s.send(create_msg("version", version_payload))
    print(f"Total sent bytes: {len(create_msg('version', version_payload))}")

    try:
        # Wait to see if Node B closes the connection
        data = s.recv(1024)
        print(f"Node response: {data.hex()}")
    except:
        print("[!] Connection closed by Node B. You are likely banned.")
    finally:
        s.close()

force_ban()


# def trigger_malicious_header():
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect(("172.20.9.230", 18333)) # Node B IP
    
#     # Message Header: Magic(4) + Command(12) + Length(4) + Checksum(4)
#     magic = b'\x0b\x11\x09\x07'
#     command = b'addr'.ljust(12, b'\x00')
    
#     # We claim the payload is 2 Gigabytes (0x7FFFFFFF)
#     # This is an instant protocol violation.
#     huge_length = struct.pack('<I', 0x7FFFFFFF) 
#     checksum = b'\x00\x00\x00\x00'
    
#     payload = magic + command + huge_length + checksum
    
#     print("[!] Sending Malicious Header (Illegal Size)...")
#     s.send(payload)
#     print(f"Total sent bytes: {len(payload)}")
#     s.close()

# trigger_malicious_header()