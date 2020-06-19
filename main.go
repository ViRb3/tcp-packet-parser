package main

import (
	"flag"
	"github.com/google/gopacket/layers"
	"log"
	"net"
)

var (
	serverPort uint
	clientPort uint
	serverIp   string
	clientIp   string
	pcapFile   string
	destDir    string
)

var (
	serverTcpPort *layers.TCPPort
	clientTcpPort *layers.TCPPort
	serverNetIp   *net.IP
	clientNetIp   *net.IP
)

func main() {
	parseFlags()
	parseFlagData()
	if err := parsePcap(pcapFile); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() {
	flag.StringVar(&serverIp, "serverIp", "", "Optional server IP filter for packets.")
	flag.UintVar(&serverPort, "serverPort", 0, "Optional server port filter for packets.")
	flag.StringVar(&clientIp, "clientIp", "", "Optional client IP filter for packets.")
	flag.UintVar(&clientPort, "clientPort", 0, "Optional client port filter for packets.")
	flag.StringVar(&pcapFile, "pcapFile", "capture.pcap", "Pcap file to parse.")
	flag.StringVar(&destDir, "destDir", "capture-dump", "Destination directory where to dump packets.")
	flag.Parse()
}

func parseFlagData() {
	if serverIp != "" {
		temp := net.ParseIP(serverIp)
		serverNetIp = &temp
	}
	if clientIp != "" {
		temp := net.ParseIP(clientIp)
		clientNetIp = &temp
	}
	if serverPort != 0 {
		temp := layers.TCPPort(serverPort)
		serverTcpPort = &temp
	}
	if clientPort != 0 {
		temp := layers.TCPPort(clientPort)
		clientTcpPort = &temp
	}
}
