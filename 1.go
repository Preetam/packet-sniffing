package main

import (
	"fmt"
	"log"
	"syscall"
)

// host order (usually little endian) -> network order (big endian)
func htons(n int) int {
	return int(int16(byte(n))<<8 | int16(byte(n>>8)))
}

func main() {
	// open a raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(syscall.ETH_P_ALL))
	if err != nil {
		log.Fatal(err)
	}

	// make a buffer to read into
	buf := make([]byte, 65536)

	for {
		// "receive from" the socket into the buf
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Fatal(err)
		}

		// print it
		fmt.Println(buf[:n])
	}
}
