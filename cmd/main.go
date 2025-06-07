package main

import (
	"fmt"
	"log"

	"github.com/songgao/water"
)

func main() {
	// TUN interface config
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = ""

	// TUN interface
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Failed to create TUN interface: %v", err)
	}
	fmt.Printf("TUN interface %s created successfully\n", iface.Name())

	// Read packets from interface
	packet := make([]byte, 2000)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Fatalf("Error reading from TUN interface: %v", err)
		}
		fmt.Printf("Read %d bytes from TUN interface % x\n", n, packet[:n])
	}
}
