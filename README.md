# TCP Packet Parser
> A PCAP analyzer that filters TCP packets and dumps them with appropriate labels.

## Introduction
When reverse-engineering custom TCP protocols, you usually begin with a log of the
communication (e.g.WireShark). You then label each client and server TCP packet, and
finally reconstruct the application-level packets from those individual packets.
This project aims to automate all of this work for you.

## Features
- Parses a PCAP file (can be exported from WireShark)
- Given IP addresses and/or ports as hints:
  - Distinguishes client and server communication
  - Merges consequent, same-source packets into a single packet
  - Performs packet re-ordering based on TCP sequence id
- Creates dump of new packets

## Limitations
- Client-server detection works only on serial communication

## Requirements
- Requires a `libpcap`-compatible library - `libpcap-dev` on Linux, or [npcap](https://nmap.org/npcap/) on Windows

## Download
Check out the [Releases](https://github.com/ViRb3/tcp-packet-parser/releases).

## Usage
```bash
$ ./tcp-packet-parser -help
```
```bash
  -clientIp string
        Optional client IP filter for packets.
  -clientPort uint
        Optional client port filter for packets.
  -destDir string
        Destination directory where to dump packets. (default "capture-dump")
  -pcapFile string
        Pcap file to parse. (default "capture.pcap")
  -serverIp string
        Optional server IP filter for packets.
  -serverPort uint
        Optional server port filter for packets.
```

### Example 1
The following command will filter all packets that contain the
port `1234` and dump them with appropriate client-server labels.
```bash
$ ./tcp-packet-parser -pcapFile "capture.pcap" -serverPort 1234
```
### Example 2
The following command will do the same as before, except that
the client-server labels will be inverted.
```bash
$ ./tcp-packet-parser -pcapFile "capture.pcap" -clientPort 1234
```
