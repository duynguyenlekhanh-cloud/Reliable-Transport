import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

PKT_TYPE_START = 0
PKT_TYPE_END = 1
PKT_TYPE_DATA = 2
PKT_TYPE_ACK = 3

MAX_CHUNK_BYTES = 1456
RTO_INTERVAL = 0.5
RECV_BUFFER_LIMIT = 2048


class BaseSender:
    def __init__(self, target_ip: str, target_port: int, window_capacity: int):
        self.dest_endpoint = (target_ip, target_port)
        self.window_capacity = window_capacity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _assemble_packet(self, pkt_type: int, seq_number: int, payload: bytes = b"") -> bytes:
        size = len(payload) if pkt_type == PKT_TYPE_DATA else 0
        hdr = PacketHeader(type=pkt_type, seq_num=seq_number, length=size, checksum=0)
        hdr.checksum = compute_checksum(hdr / payload)
        return bytes(hdr / payload)

    def _inspect_ack(self, raw_bytes: bytes):
        if len(raw_bytes) < 16:
            return None

        hdr = PacketHeader(raw_bytes[:16])
        if len(raw_bytes) < 16 + hdr.length:
            return None

        payload = raw_bytes[16 : 16 + hdr.length]
        pkt_chk = hdr.checksum
        hdr.checksum = 0

        if pkt_chk != compute_checksum(hdr / payload):
            return None

        if hdr.type != PKT_TYPE_ACK:
            return None

        return hdr.seq_num

    def _establish_session(self):
        start_msg = self._assemble_packet(PKT_TYPE_START, 0, b"")
        while True:
            self.sock.sendto(start_msg, self.dest_endpoint)
            ready_r, _, _ = select.select([self.sock], [], [], RTO_INTERVAL)
            if ready_r:
                try:
                    resp_bytes, _ = self.sock.recvfrom(RECV_BUFFER_LIMIT)
                except socket.error:
                    continue
                ack_no = self._inspect_ack(resp_bytes)
                if ack_no is not None:
                    break

    def _terminate_session(self, final_seq: int):
        end_msg = self._assemble_packet(PKT_TYPE_END, final_seq, b"")
        self.sock.sendto(end_msg, self.dest_endpoint)

        deadline = time.time() + RTO_INTERVAL
        while time.time() < deadline:
            wait_time = max(0.0, deadline - time.time())
            ready_r, _, _ = select.select([self.sock], [], [], wait_time)
            if ready_r:
                try:
                    resp_bytes, _ = self.sock.recvfrom(RECV_BUFFER_LIMIT)
                except socket.error:
                    continue
                ack_no = self._inspect_ack(resp_bytes)
                if ack_no is not None and ack_no >= final_seq:
                    break

    def transmit_stream(self, data_stream: bytes):
        payload_blocks = []
        if len(data_stream) > 0:
            for offset in range(0, len(data_stream), MAX_CHUNK_BYTES):
                payload_blocks.append(data_stream[offset : offset + MAX_CHUNK_BYTES])
        total_count = len(payload_blocks)

        packet_registry = {}
        for idx in range(1, total_count + 1):
            packet_registry[idx] = self._assemble_packet(PKT_TYPE_DATA, idx, payload_blocks[idx - 1])

        self._establish_session()

        window_base = 1
        frontier_seq = 1
        timer_started_at = None

        while window_base <= total_count:
            while frontier_seq < window_base + self.window_capacity and frontier_seq <= total_count:
                self.sock.sendto(packet_registry[frontier_seq], self.dest_endpoint)
                if timer_started_at is None:
                    timer_started_at = time.time()
                frontier_seq += 1

            if timer_started_at is not None:
                passed = time.time() - timer_started_at
                time_left = RTO_INTERVAL - passed
                if time_left <= 0:
                    for seq in range(window_base, frontier_seq):
                        self.sock.sendto(packet_registry[seq], self.dest_endpoint)
                    timer_started_at = time.time()
                    time_left = RTO_INTERVAL
            else:
                time_left = RTO_INTERVAL

            ready_r, _, _ = select.select([self.sock], [], [], max(0.0, time_left))
            if ready_r:
                try:
                    resp_bytes, _ = self.sock.recvfrom(RECV_BUFFER_LIMIT)
                except socket.error:
                    continue

                ack_seq = self._inspect_ack(resp_bytes)
                if ack_seq is not None and ack_seq > window_base:
                    window_base = min(ack_seq, total_count + 1)
                    if window_base < frontier_seq:
                        timer_started_at = time.time()
                    else:
                        timer_started_at = None

        self._terminate_session(total_count + 1)
        self.sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    input_payload = sys.stdin.buffer.read()
    sender_app = BaseSender(args.receiver_ip, args.receiver_port, args.window_size)
    sender_app.transmit_stream(input_payload)


if __name__ == "__main__":
    main()
