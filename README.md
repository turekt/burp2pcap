# Burp HTTP history XML to PCAP

This quickly assembled source code converts exported HTTP history XML file from Burp to a valid PCAP file. 
Benefits of using a PCAP file instead of raw XML export are:
- improved overview of issued requests and responses
- improved filtering and searching
- better alternative when sharing traffic information

There are two variants written, one in Python with scapy and second in Go with gopacket. 
Instructions on how to run the variants are in their corresponding implementation files.

Both implementation variants create a sample Ethernet, IP and TCP packet which wraps the actual HTTP content from export. 
In order for the packets to not be registered as TCP retransmission by Wireshark dissector, each packet uses a different port, forcing each packet to be presented as HTTP.

Since this is only a simple implementation best used as template, there are several obvious improvements possible:
- IPv6 support
- actual target IP is extracted but not used in the PCAP file (requires IPv6 support first)
- HTTP content size is limited and reduced due to wireshark single packet size limitations (in reality bigger HTTP content is reassembled from multiple TCP packets which is not covered in this simple script)
- removing port increments and mimick actual TCP communication which will force Wireshark to properly assemble HTTP content
