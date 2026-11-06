import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

PKT_TYPE_START = 0
PKT_TYPE_END = 1
PKT_TYPE_DATA = 2
PKT_TYPE_ACK = 3

HEADER_LENGTH = 16
RECV_BUFFER_SIZE = 2048


class OptReceiver:
    def __init__(self, bind_ip: str, bind_port: int, window_capacity: int):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.window_capacity = window_capacity

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))

        self.sender_endpoint = None
        self.session_active = False

        self.expected_seq = 1
        self.buffered_packets = {}
        self.end_pkt_seen = False
        self.end_seq_num = None

    def _pack_packet(self, pkt_type: int, seq_number: int, payload: bytes = b"") -> bytes:
        size = len(payload) if pkt_type == PKT_TYPE_DATA else 0
        hdr = PacketHeader(type=pkt_type, seq_num=seq_number, length=size, checksum=0)
        hdr.checksum = compute_checksum(hdr / payload)
        return bytes(hdr / payload)

    def _parse_packet(self, raw_bytes: bytes):
        if len(raw_bytes) < HEADER_LENGTH:
            return None, None

        hdr = PacketHeader(raw_bytes[:HEADER_LENGTH])
        if len(raw_bytes) < HEADER_LENGTH + hdr.length:
            return None, None

        payload = raw_bytes[HEADER_LENGTH : HEADER_LENGTH + hdr.length]
        received_checksum = hdr.checksum
        hdr.checksum = 0

        if received_checksum != compute_checksum(hdr / payload):
            return None, None

        return hdr, payload

    def _deliver_payload(self, data: bytes):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def _send_ack(self, ack_num: int):
        if self.sender_endpoint:
            ack_datagram = self._pack_packet(PKT_TYPE_ACK, ack_num)
            self.sock.sendto(ack_datagram, self.sender_endpoint)

    def listen(self):
        while True:
            try:
                raw_bytes, endpoint = self.sock.recvfrom(RECV_BUFFER_SIZE)
            except socket.error:
                continue

            hdr, payload = self._parse_packet(raw_bytes)
            if hdr is None:
                continue

            if not self.session_active:
                if hdr.type == PKT_TYPE_START:
                    self.session_active = True
                    self.sender_endpoint = endpoint
                    self.expected_seq = 1
                    self.buffered_packets.clear()
                    self.end_pkt_seen = False
                    self.end_seq_num = None
                    self._send_ack(1)
                continue

            if endpoint != self.sender_endpoint:
                continue

            if hdr.type == PKT_TYPE_START:
                continue

            if hdr.type == PKT_TYPE_DATA:
                seq = hdr.seq_num

                if seq >= self.expected_seq + self.window_capacity:
                    continue

                if seq < self.expected_seq:
                    self._send_ack(seq)
                elif seq == self.expected_seq:
                    self._deliver_payload(payload)
                    self.expected_seq += 1

                    while self.expected_seq in self.buffered_packets:
                        self._deliver_payload(self.buffered_packets.pop(self.expected_seq))
                        self.expected_seq += 1

                    self._send_ack(seq)

                    if self.end_pkt_seen and self.expected_seq == self.end_seq_num:
                        self._send_ack(self.end_seq_num)
                        break
                else:
                    self.buffered_packets[seq] = payload
                    self._send_ack(seq)

            elif hdr.type == PKT_TYPE_END:
                seq = hdr.seq_num
                if seq == self.expected_seq:
                    self._send_ack(seq)
                    break
                elif seq > self.expected_seq:
                    self.end_pkt_seen = True
                    self.end_seq_num = seq
                    self._send_ack(seq)

        self.sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    recv_app = OptReceiver(args.receiver_ip, args.receiver_port, args.window_size)
    recv_app.listen()


if __name__ == "__main__":
    main()
