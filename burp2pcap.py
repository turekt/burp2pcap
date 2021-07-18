# apt install python3-scapy python3-xmltodict
# python3 burp2pcap.py TARGET_XML_FILE

from scapy.all import Ether, IP, TCP, PcapWriter
from scapy.layers.http import HTTP

import argparse
import base64
import json
import sys
import xmltodict

XML_KEY_ITEMS = "items"
XML_KEY_ITEM = "item"

XML_KEY_RAW_VALUE = "#text"
XML_KEY_RAW_BASE64 = "@base64"
XML_KEY_RAW_REQUEST = "request"
XML_KEY_RAW_RESPONSE = "response"

C_IP = "127.0.0.1"
H_IP = "127.0.0.2"
H_PORT = 80

PORT_OFFSET = 1024
WSHARK_MAX_PKT_LEN = 262090

def read_xml_items(filepath):
    with open(filepath, 'r') as fp:
        xml_content = fp.read()

    items_dict = xmltodict.parse(xml_content)
    return reversed(items_dict[XML_KEY_ITEMS][XML_KEY_ITEM])

def write_packet(writer, ip_tcp_layers, item, item_key):
    raw = item[item_key]
    text = raw[XML_KEY_RAW_VALUE]
    data = base64.b64decode(text) if raw[XML_KEY_RAW_BASE64] else text
    data = data[:WSHARK_MAX_PKT_LEN] if len(data) > WSHARK_MAX_PKT_LEN else data
    pkt = Ether()/ip_tcp_layers/HTTP(data)
    writer.write(pkt)

def write_pcap(filepath, items):
    writer = PcapWriter(filepath, sync=True)
    for i, item in enumerate(items):
        cport = i + PORT_OFFSET
        layer = IP(len=65535, src=C_IP, dst=H_IP)/TCP(sport=cport, dport=H_PORT)
        write_packet(writer, layer, item, XML_KEY_RAW_REQUEST)
        layer = IP(len=65535, src=H_IP, dst=C_IP)/TCP(sport=H_PORT, dport=cport)
        write_packet(writer, layer, item, XML_KEY_RAW_RESPONSE)
    writer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Burp HTTP history to PCAP")
    parser.add_argument("--out", help="output filepath", default="out.pcap")
    parser.add_argument("target", help="Burp HTTP history target file")
    args = parser.parse_args()

    items = read_xml_items(args.target)
    write_pcap(args.out, items)
