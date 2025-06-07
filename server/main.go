package main

import (
	"fmt"
	"log"
	"net"

	"github.com/Chrissie21/myproject/crypto"
)

var sharedKey = []byte("0123456789ABCDEF0123456789ABCDEF")

func main() {
	addr := net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8080,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("[server] UDP listen error: %v", err)
	}
	defer conn.Close()

	fmt.Println("[server] VPN server listening on UDP", addr.String())

	vpnCrypto, err := crypto.NewVPNCrypto(sharedKey)
	if err != nil {
		log.Fatalf("[server] Crypto init error: %v", err)
	}

	buf := make([]byte, 2000)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("[server] Read error:", err)
			continue
		}

		fmt.Printf("[server] Received %d bytes from %s\n", n, clientAddr)

		decrypted, err := vpnCrypto.Decrypt(buf[:n])
		if err != nil {
			log.Println("[server] Decryption failed:", err)
			continue
		}

		fmt.Printf("[>] Decrypted %d bytes from %s: %x\n", len(decrypted), clientAddr, decrypted)

		encrypted, err := vpnCrypto.Encrypt(decrypted)
		if err != nil {
			log.Println("[server] Encryption failed:", err)
			continue
		}

		_, err = conn.WriteToUDP(encrypted, clientAddr)
		if err != nil {
			log.Println("[server] Write error:", err)
		} else {
			fmt.Printf("[<] Sent back %d bytes to %s\n", len(encrypted), clientAddr)
		}
	}
}
