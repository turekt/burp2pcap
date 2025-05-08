# Burp HTTP history XML to PCAP

You can also utilize this implementation directly from Burp via [BurpHistory2Pcap Burp extension](https://github.com/turekt/burphistory2pcap).

This quickly assembled script converts exported HTTP history XML file from Burp to a valid PCAP file. 

Benefits of using a PCAP file instead of raw XML export are:
- improved overview of issued requests and responses
- improved filtering and searching
- better alternative when sharing traffic information

## Running

To run with default options:
```
apt install python3-scapy python3-xmltodict
python3 burp2pcap.py history.xml
```

