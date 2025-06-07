package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	// UDP listener
	addr := net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8080,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP port 8080: %v", err)
	}
	defer conn.Close()

	fmt.Printf("VPN server listening on %s\n", addr.String())

	// Receiving and echo packets
	packet := make([]byte, 2000)
	for {
		n, clientAddr, err := conn.ReadFromUDP(packet)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		fmt.Printf("[>] Received %d bytes from %s\n", n, clientAddr)

		// Echo packets back
		_, err = conn.WriteToUDP(packet[:n], clientAddr)
		if err != nil {
			log.Printf("Write error: %v", err)
		} else {
			fmt.Printf("[<] Echoed %d bytes back to %s\n", n, clientAddr)
		}
	}
}
