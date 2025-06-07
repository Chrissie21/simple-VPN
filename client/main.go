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
	"os/exec"
	"time"

	"github.com/Chrissie21/myproject/crypto"
	"github.com/songgao/water"
)

var sharedKey = []byte("0123456789ABCDEF0123456789ABCDEF")
var magic = []byte("VPN1")

func main() {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("[client] Failed to create TUN: %v", err)
	}
	fmt.Printf("[client] TUN interface %s created.\n", iface.Name())

	conn, err := net.Dial("udp", "10.211.55.7:8080")
	if err != nil {
		log.Fatalf("[client] Failed to connect to VPN server: %v", err)
	}
	defer conn.Close()

	clientIP, err := sendHandshake(conn)
	if err != nil {
		log.Fatal("[client] Handshake failed:", err)
	}

	// Configure TUN interface with assigned IP
	cmd := exec.Command("ifconfig", iface.Name(), clientIP.String(), "10.0.0.1", "netmask", "255.255.255.0", "up")
	if err := cmd.Run(); err != nil {
		log.Fatalf("[client] Failed to configure TUN IP: %v", err)
	}

	vpnCrypto, err := crypto.NewVPNCrypto(sharedKey)
	if err != nil {
		log.Fatalf("[client] Failed to init crypto: %v", err)
	}

	buf := make([]byte, 1500)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Println("[client] Goroutine panic:", r)
			}
		}()

		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Println("[client] Read error from server:", err)
				continue
			}

			fmt.Printf("[client] received %d bytes from server\n", n)

			decrypted, err := vpnCrypto.Decrypt(buf[:n])
			if err != nil {
				log.Println("[client] Decryption error:", err)
				continue
			}

			fmt.Printf("[client] decrypted packet (%d bytes): %x\n", len(decrypted), decrypted)

			_, err = iface.Write(decrypted)
			if err != nil {
				log.Println("[client] TUN write error:", err)
			}
		}
	}()

	fmt.Println("[client] Connected to VPN server at", conn.RemoteAddr())

	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Println("[client] Read error from TUN:", err)
			continue
		}

		encrypted, err := vpnCrypto.Encrypt(buf[:n])
		if err != nil {
			log.Println("[client] Encryption error:", err)
			continue
		}

		_, err = conn.Write(encrypted)
		if err != nil {
			log.Println("[client] Write error to server:", err)
		}
	}
}

func sendHandshake(conn net.Conn) (net.IP, error) {
	ts := time.Now().Unix()
	buf := new(bytes.Buffer)

	buf.Write(magic)
	binary.Write(buf, binary.BigEndian, ts)
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(magic)
	binary.Write(mac, binary.BigEndian, ts)
	hmacBytes := mac.Sum(nil)
	buf.Write(hmacBytes)

	log.Printf("[client] Sent handshake: magic=%x, ts=%d, hmac=%x", magic, ts, hmacBytes)

	_, err := conn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}

	// Read server response
	respBuf := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("set read deadline failed: %v", err)
	}
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %v", err)
	}

	log.Printf("[client] Response length: %d bytes, raw=%x", n, respBuf[:n])

	if n < 16+32 {
		return nil, fmt.Errorf("response too short: %d bytes", n)
	}

	r := bytes.NewReader(respBuf[:n])
	recvMagic := make([]byte, 4)
	r.Read(recvMagic)
	if !bytes.Equal(recvMagic, magic) {
		return nil, fmt.Errorf("invalid magic in response: %x", recvMagic)
	}

	var serverTs int64
	binary.Read(r, binary.BigEndian, &serverTs)
	if math.Abs(float64(time.Now().Unix()-serverTs)) > 10 {
		return nil, fmt.Errorf("server timestamp too far off: %d", serverTs)
	}

	clientIP := make([]byte, 4)
	r.Read(clientIP)

	mac.Reset()
	mac.Write(respBuf[:16]) // Magic (4) + timestamp (8) + IP (4)
	expectedHMAC := mac.Sum(nil)
	recvHMAC := make([]byte, 32)
	if _, err := r.Read(recvHMAC); err != nil || len(recvHMAC) != 32 {
		return nil, fmt.Errorf("failed to read HMAC: %v", err)
	}

	log.Printf("[client] Received response: magic=%x, ts=%d, ip=%v, hmac=%x", recvMagic, serverTs, net.IP(clientIP), recvHMAC)
	log.Printf("[client] Expected HMAC: %x", expectedHMAC)
	log.Printf("[client] Data hashed for HMAC: %x", respBuf[:16])

	if !hmac.Equal(expectedHMAC, recvHMAC) {
		return nil, fmt.Errorf("HMAC mismatch in response")
	}

	return net.IP(clientIP), nil
}
