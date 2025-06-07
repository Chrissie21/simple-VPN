package main

import (
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
)

func main() {
	// Create a TUN interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("TUN creation error: %v", err)
	}
	fmt.Printf("TUN interface %s created.\n", iface.Name())

	// UDP connection to VPN server
	serverAddr := "127.0.0.1:8080"
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to connect to VPN server: %v", err)
	}
	defer conn.Close()

	fmt.Println("Connected to VPN server at", serverAddr)

	// read from TUN --> send over UDP
	packet := make([]byte, 2000)
	go func() {
		for {
			n, err := iface.Read(packet)
			if err != nil {
				log.Fatalf("Error reading from TUN: %v", err)
			}
			fmt.Printf("[>] Sending %d bytes to server\n", n)

			_, err = conn.Write(packet[:n])
			if err != nil {
				log.Fatalf("Error sending UDP packet: %v", err)
			}
		}
	}()

	// Listen for incoming packets from the server
	buf := make([]byte, 2000)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Error reading from server: %v", err)
		}
		fmt.Printf("[<] Received %d bytes from server\n", n)

		// Write the received packet to the TUN interface
		if _, err := iface.Write(buf[:n]); err != nil {
			log.Fatalf("Error writing to TUN interface: %v", err)
		}
		fmt.Printf("[>] Sent %d bytes to TUN interface\n", n)
	}
}
