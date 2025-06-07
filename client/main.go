package main

import (
	"fmt"
	"log"
	"net"

	"github.com/Chrissie21/myproject/crypto"
	"github.com/songgao/water"
)

var sharedKey = []byte("0123456789ABCDEF0123456789ABCDEF")

func main() {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("Failed to create TUN: %v", err)
	}
	fmt.Printf("TUN interface %s created.\n", iface.Name())

	conn, err := net.Dial("udp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("Failed to connect to VPN server: %v", err)
	}
	defer conn.Close()

	vpnCrypto, err := crypto.NewVPNCrypto(sharedKey)
	if err != nil {
		log.Fatalf("Failed to init crypto: %v", err)
	}

	buf := make([]byte, 2000)
	go func() {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Println("Read error from server:", err)
				continue
			}

			decrypted, err := vpnCrypto.Decrypt(buf[:n])
			if err != nil {
				log.Println("Decryption error:", err)
				continue
			}

			iface.Write(decrypted)
		}
	}()

	fmt.Println("Connected to VPN server at 127.0.0.1:8080")

	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Println("Read error from TUN:", err)
			continue
		}

		encrypted, err := vpnCrypto.Encrypt(buf[:n])
		if err != nil {
			log.Println("Encryption error:", err)
			continue
		}

		conn.Write(encrypted)
	}
}
