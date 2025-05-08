# apt install python3-scapy python3-xmltodict
# python3 burp2pcap.py TARGET_XML_FILE

from scapy.all import Ether, IP, TCP, PcapWriter, Raw

import argparse
import base64
import json
import sys
import xmltodict

XML_KEY_ITEMS = "items"
XML_KEY_ITEM = "item"

XML_KEY_RAW_IP = "@ip"
XML_KEY_RAW_HOST = "host"
XML_KEY_RAW_PORT = "port"
XML_KEY_RAW_VALUE = "#text"
XML_KEY_RAW_BASE64 = "@base64"
XML_KEY_RAW_REQUEST = "request"
XML_KEY_RAW_RESPONSE = "response"

DEFAULT_CLIENT_MAC = "00:62:75:72:70:31"
DEFAULT_SERVER_MAC = "00:62:75:72:70:32"
DEFAULT_CLIENT_IP = "127.0.0.1"
DEFAULT_SERVER_IP = "127.0.0.2"
DEFAULT_SERVER_PORT = 80

class Endpoint:

    def __init__(self, mac, ip, port, isn):
        self.mac = mac
        self.ip = ip
        self.port = port
        self.seq = isn

class Burp2Pcap:

    MSS = 65495

    def __init__(self, outfile, use_real_server_ip=True, use_real_server_port=False):
        self.writer = PcapWriter(outfile, sync=True, linktype=1)
        self.use_real_server_ip = use_real_server_ip
        self.use_real_server_port = use_real_server_port
        self.inc = 0

    def write_handshake(self, src, dst):
        syn = self._mkpkt('S', src, dst)
        syn['TCP'].options=[('MSS', Burp2Pcap.MSS)]
        self._write_pkt(syn)
        src.seq += 1

        synack = self._mkpkt('SA', dst, src)
        syn['TCP'].options=[('MSS', Burp2Pcap.MSS)]
        self._write_pkt(synack)
        dst.seq += 1

        ack = self._mkpkt('A', src, dst)
        self._write_pkt(ack)

    def write_teardown(self, src, dst):
        fin = self._mkpkt('FA', src, dst)
        self._write_pkt(fin)

        finack = self._mkpkt('FA', dst, src)
        self._write_pkt(finack)

        src.seq += 1
        dst.seq += 1
        ack = self._mkpkt('A', src, dst)
        self._write_pkt(ack)

    def write_packet_chunked(self, src, dst, raw):
        text = raw.get(XML_KEY_RAW_VALUE, "")
        data = base64.b64decode(text) if raw[XML_KEY_RAW_BASE64] else text

        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + Burp2Pcap.MSS]
            pkt = self._mkpkt('PA', src, dst, Raw(chunk))
            self._write_pkt(pkt)
            src.seq += len(chunk)
            offset += len(chunk)

        ack = self._mkpkt('A', dst, src)
        self._write_pkt(ack)
        return src.seq

    def _mkpkt(self, tcp_flags, src, dst, payload=None):
        base = Ether(src=src.mac, dst=dst.mac)/IP(src=src.ip, dst=dst.ip)/TCP(sport=src.port, dport=dst.port, flags=tcp_flags, seq=src.seq, ack=dst.seq)
        return base/payload if payload else base

    def _write_pkt(self, pkt):
        pkt.window = 65535
        pkt.time = self.inc * 0.01
        self.writer.write(pkt)
        self.inc += 1

    def write_pcap(self, items):
        for i in range(0, len(items)):
            item = items[i]
            src, dst = self.determine_endpoints(i, item)
            self.write_handshake(src, dst)
            src.seq = self.write_packet_chunked(src, dst, item[XML_KEY_RAW_REQUEST])
            dst.seq = self.write_packet_chunked(dst, src, item[XML_KEY_RAW_RESPONSE])
            self.write_teardown(dst, src)

    def determine_endpoints(self, idx, item):
        client_ip = DEFAULT_CLIENT_IP
        client_port = 10000 + idx
        client_isn = 10000 + idx * 10
        server_ip = DEFAULT_SERVER_IP
        server_port = DEFAULT_SERVER_PORT
        server_isn = 50000 + idx * 10

        if self.use_real_server_ip:
            if XML_KEY_RAW_HOST in item:
                host = item[XML_KEY_RAW_HOST]
                if XML_KEY_RAW_IP in host:
                    server_ip = host[XML_KEY_RAW_IP]

        if self.use_real_server_port:
            if XML_KEY_RAW_PORT in item:
                port = item[XML_KEY_RAW_PORT]
                server_port = int(port) if port.isdigit() else DEFAULT_SERVER_PORT

        client = Endpoint(DEFAULT_CLIENT_MAC, client_ip, client_port, client_isn)
        server = Endpoint(DEFAULT_SERVER_MAC, server_ip, server_port, server_isn)
        return client, server

    def close(self):
        self.writer.close()

def read_xml_items(filepath):
    with open(filepath, 'r') as fp:
        xml_content = fp.read()

    items_dict = xmltodict.parse(xml_content)
    return items_dict[XML_KEY_ITEMS][XML_KEY_ITEM]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Burp HTTP history to PCAP")
    parser.add_argument("--out", help="output filepath", default="out.pcap")
    parser.add_argument("target", help="Burp HTTP history target file")
    parser.add_argument('--use-real-server-ip', dest='use_real_server_ip', action='store_true')
    parser.add_argument('--no-use-real-server-ip', dest='use_real_server_ip', action='store_false')
    parser.set_defaults(use_real_server_ip=True)
    parser.add_argument('--use-real-server-port', dest='use_real_server_port', action='store_true')
    parser.add_argument('--no-use-real-server-port', dest='use_real_server_port', action='store_false')
    parser.set_defaults(use_real_server_port=False)
    args = parser.parse_args()

    items = read_xml_items(args.target)
    b2p = Burp2Pcap(args.out, args.use_real_server_ip, args.use_real_server_port)
    b2p.write_pcap(items)
    b2p.close()
