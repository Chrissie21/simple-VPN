package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/Chrissie21/myproject/crypto"
)

var sharedKey = []byte("0123456789ABCDEF0123456789ABCDEF")
var magic = []byte("VPN1")

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

	clients := make(map[string]bool) // Track authenticated clients

	buf := make([]byte, 2000)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("[server] Read error:", err)
			continue
		}

		if !clients[clientAddr.String()] {
			if handleHandshake(conn, clientAddr, buf[:n]) {
				clients[clientAddr.String()] = true
				log.Println("[server] Handshake succeeded for", clientAddr)
			} else {
				log.Println("Handshake failed from", clientAddr)
				continue
			}
		} else {
			// Handle encrypted packets here
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
}

func handleHandshake(conn *net.UDPConn, addr *net.UDPAddr, data []byte) bool {
	if len(data) < 4+8+32 {
		log.Println("Handshake too short")
		return false
	}

	r := bytes.NewReader(data)

	recvMagic := make([]byte, 4)
	r.Read(recvMagic)
	if !bytes.Equal(recvMagic, magic) {
		log.Println("Invalid magic")
		return false
	}

	var ts int64
	binary.Read(r, binary.BigEndian, &ts)

	if math.Abs(float64(time.Now().Unix()-ts)) > 10 {
		log.Println("Timestamp too far off")
		return false
	}

	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(recvMagic)
	binary.Write(mac, binary.BigEndian, ts)
	expectedHMAC := mac.Sum(nil)

	recvHMAC := make([]byte, 32)
	r.Read(recvHMAC)

	if !hmac.Equal(expectedHMAC, recvHMAC) {
		log.Println("HMAC mismatch")
		return false
	}

	log.Println("Client authenticated from", addr)
	return true
}
