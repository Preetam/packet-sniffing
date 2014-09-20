package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/PreetamJinka/ethernetdecode"
)

// convert to network order
func htons(n int) int {
	return int(int16(byte(n))<<8 | int16(byte(n>>8)))
}

func main() {
	log.SetOutput(os.Stdout)

	tcpPort := flag.Uint64("port", 3306, "destination/source TCP port to sniff")
	flag.Parse()

	// open a raw socket for sniffing
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_ALL))
	if err != nil {
		log.Fatal(err, " - are you running as root?")
	}

	// much larger than MTU, just to be safe
	buf := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Fatal(err)
		}

		// decode the Ethernet packet and save the protocol header
		_, iphdr, protohdr := ethernetdecode.Decode(buf[:n])

		// check for a TCP header
		tcphdr, ok := protohdr.(ethernetdecode.TcpHeader)
		if ok {
			var source net.IP
			var dest net.IP
			switch iphdr.(type) {
			case ethernetdecode.Ipv4Header:
				ipBytes := iphdr.(ethernetdecode.Ipv4Header).Source
				source = net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
				ipBytes = iphdr.(ethernetdecode.Ipv4Header).Destination
				dest = net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

			case ethernetdecode.Ipv6Header:
				ipBytes := iphdr.(ethernetdecode.Ipv6Header).Source
				source = net.IP(ipBytes[:])
				ipBytes = iphdr.(ethernetdecode.Ipv6Header).Destination
				dest = net.IP(ipBytes[:])
			}

			// now for the magic.
			if tcphdr.DestinationPort == uint16(*tcpPort) || tcphdr.SourcePort == uint16(*tcpPort) {
				log.Println("---")

				if tcphdr.DestinationPort == uint16(*tcpPort) {
					log.Printf("%v:%d => %v:%d", source, tcphdr.SourcePort, dest, tcphdr.DestinationPort)
				} else {
					log.Printf("%v:%d <= %v:%d", dest, tcphdr.DestinationPort, source, tcphdr.SourcePort)
				}

				// SYN flag, but not ACK
				if tcphdr.Flags&3 == 2 {
					// we're seeing a connection being opened
					log.Print("Connection opened.")
					continue
				}

				// FIN + ACK
				if tcphdr.Flags&17 == 17 {
					// we're seeing a connection being opened
					log.Print("Connection closed.")
					continue
				}

				fmt.Printf("Payload length = %d\n\n%s", len(tcphdr.Payload), tcphdr.Payload)
			}
		}
	}
}
