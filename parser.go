package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
)

type PacketSource string

const (
	PACKET_FROM_SERVER = "server"
	PACKET_FROM_CLIENT = "client"
	PACKET_UNKNOWN     = ""
)

var dataPieces = make(map[uint32][]byte)
var lastPacketSource = PacketSource(PACKET_UNKNOWN)
var lastPacketId = 0

func parsePcap(file string) error {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetNumber := 0
	for packet := range packetSource.Packets() {
		packetNumber++
		var srcIP net.IP
		var dstIP net.IP
		for _, layer := range packet.Layers() {
			if layer.LayerType() == layers.LayerTypeIPv4 {
				ipv4Layer := layer.(*layers.IPv4)
				srcIP = ipv4Layer.SrcIP
				dstIP = ipv4Layer.DstIP
			} else if layer.LayerType() == layers.LayerTypeTCP {
				tcpLayer := layer.(*layers.TCP)
				if err := parseTcpLayer(tcpLayer, packetNumber, srcIP, dstIP); err != nil {
					log.Println(err)
					break
				}
			}
		}
	}

	return nil
}

func parseTcpLayer(layer *layers.TCP, id int, srcIP net.IP, dstIP net.IP) error {
	packetSource := getPacketSource(srcIP, layer.SrcPort, dstIP, layer.DstPort)
	if packetSource == PACKET_UNKNOWN || len(layer.Payload) < 1 {
		return nil
	}

	if packetSource != lastPacketSource && len(dataPieces) > 0 {
		if err := flushDataPieces(lastPacketId, lastPacketSource); err != nil {
			return err
		}
	}

	dataPieces[layer.Seq] = layer.Payload
	lastPacketSource = packetSource
	lastPacketId = id
	return nil
}

func flushDataPieces(id int, packetType PacketSource) error {
	packets := ReconstructPackets(dataPieces)
	dataPieces = make(map[uint32][]byte)

	dstPath := filepath.Join(destDir, fmt.Sprintf("%d-%s", id, packetType))
	if err := os.MkdirAll(filepath.Dir(dstPath), 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(dstPath, packets, 0600); err != nil {
		return err
	}
	return nil
}

func getPacketSource(srcIP net.IP, srcPort layers.TCPPort, dstIP net.IP, dstPort layers.TCPPort) PacketSource {
	var matches []PacketSource
	if serverNetIp != nil {
		if serverNetIp.Equal(srcIP) {
			matches = append(matches, PACKET_FROM_SERVER)
		} else if serverNetIp.Equal(dstIP) {
			matches = append(matches, PACKET_FROM_CLIENT)
		} else {
			return PACKET_UNKNOWN
		}
	}
	if clientNetIp != nil {
		if clientNetIp.Equal(srcIP) {
			matches = append(matches, PACKET_FROM_CLIENT)
		} else if clientNetIp.Equal(dstIP) {
			matches = append(matches, PACKET_FROM_SERVER)
		} else {
			return PACKET_UNKNOWN
		}
	}
	if serverTcpPort != nil {
		if *serverTcpPort == srcPort {
			matches = append(matches, PACKET_FROM_SERVER)
		} else if *serverTcpPort == dstPort {
			matches = append(matches, PACKET_FROM_CLIENT)
		} else {
			return PACKET_UNKNOWN
		}
	}
	if clientTcpPort != nil {
		if *clientTcpPort == srcPort {
			matches = append(matches, PACKET_FROM_CLIENT)
		} else if *clientTcpPort == dstPort {
			matches = append(matches, PACKET_FROM_SERVER)
		} else {
			return PACKET_UNKNOWN
		}
	}

	return getPacketSourceFromMatches(matches)
}

func getPacketSourceFromMatches(matches []PacketSource) PacketSource {
	switch len(matches) {
	case 0:
		return PACKET_UNKNOWN
	case 1:
		return matches[0]
	default:
		firstMatch := matches[0]
		for _, match := range matches {
			if match != firstMatch {
				return PACKET_UNKNOWN
			}
		}
		return firstMatch
	}
}
