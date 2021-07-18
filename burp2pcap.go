// go mod init burp2pcap
// go run burp2pcap.go TARGET_XML_FILE

package main

import (
	"encoding/base64"
	"encoding/xml"
	"flag"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

const (
	timeLayout       = "Mon Jan 2 15:04:05 MST 2006"
	wsharkMaxPktSize = 262104
	portOffset       = 1024
)

var (
	hostPort      = layers.TCPPort(80)
	localhostIPv4 = net.IP{127, 0, 0, 1}
	targetIPv4    = net.IP{127, 0, 0, 2}
)

type Items struct {
	XMLName xml.Name `xml:"items"`
	List    []Item   `xml:"item"`
}

type Item struct {
	XMLName  xml.Name `xml:"item"`
	Time     string   `xml:"time"`
	Host     HostIP   `xml:"host"`
	Request  Raw      `xml:"request"`
	Response Raw      `xml:"response"`
}

type HostIP struct {
	Host string `xml:",chardata"`
	IP   string `xml:"ip,attr"`
}

type Raw struct {
	Data   string `xml:",chardata"`
	Base64 bool   `xml:"base64,attr"`
}

type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
	Data      []byte
}

func readXML(filepath string) (*Items, error) {
	exportFile, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer exportFile.Close()

	fileBytes, err := ioutil.ReadAll(exportFile)
	if err != nil {
		return nil, err
	}

	var i Items
	if err := xml.Unmarshal(fileBytes, &i); err != nil {
		return nil, err
	}
	return &i, nil
}

func rawToBytes(r *Raw) []byte {
	var err error
	var data []byte
	if r.Base64 {
		data, err = base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			data = []byte(r.Data)
		}
	} else {
		data = []byte(r.Data)
	}
	return data
}

func writePacket(w *pcapgo.Writer, p *Packet) error {
	ipv4 := &layers.IPv4{
		SrcIP:    p.SrcIP,
		DstIP:    p.DstIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := layers.TCP{
		SrcPort: p.SrcPort,
		DstPort: p.DstPort,
		PSH:     true,
		ACK:     true,
		Ack:     1,
		Seq:     1,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ipv4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if len(p.Data) > wsharkMaxPktSize {
		p.Data = p.Data[:wsharkMaxPktSize]
	}

	payload := gopacket.Payload(p.Data)
	if err := gopacket.SerializeLayers(buf, opts, ipv4, &tcp, payload); err != nil {
		return err
	}
	data := buf.Bytes()

	capInfo := gopacket.CaptureInfo{
		Timestamp:     p.Timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}
	w.WritePacket(capInfo, data)
	return nil
}

func writePCAP(filepath string, items *Items) error {
	pcapFile, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer pcapFile.Close()

	pcapWriter := pcapgo.NewWriter(pcapFile)
	pcapWriter.WriteFileHeader(65536, layers.LinkTypeIPv4)
	for i := len(items.List) - 1; i >= 0; i-- {
		item := items.List[i]
		t, err := time.Parse(timeLayout, item.Time)
		if err != nil {
			return err
		}

		requestP := &Packet{
			Timestamp: t,
			SrcIP:     localhostIPv4,
			DstIP:     targetIPv4,
			SrcPort:   layers.TCPPort(i + portOffset),
			DstPort:   hostPort,
			Data:      rawToBytes(&item.Request),
		}
		writePacket(pcapWriter, requestP)

		responseP := &Packet{
			Timestamp: t,
			SrcIP:     targetIPv4,
			DstIP:     localhostIPv4,
			SrcPort:   hostPort,
			DstPort:   layers.TCPPort(i + portOffset),
			Data:      rawToBytes(&item.Response),
		}
		writePacket(pcapWriter, responseP)
	}

	return nil
}

func main() {
	outPtr := flag.String("out", "out.pcap", "output filepath")
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		log.Fatalln("please specify history XML file")
	}

	items, err := readXML(args[0])
	if err != nil {
		panic(err)
	}

	if err := writePCAP(*outPtr, items); err != nil {
		panic(err)
	}
}
