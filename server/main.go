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
	"sync"
	"time"

	"github.com/Chrissie21/myproject/crypto"
	"github.com/songgao/water"
)

var sharedKey = []byte("0123456789ABCDEF0123456789ABCDEF")
var magic = []byte("VPN1")

type ClientSession struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
	ClientIP net.IP
}

func main() {
	// Create TUN interface
	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("[server] Failed to create TUN: %v", err)
	}
	fmt.Printf("[server] TUN interface %s created\n", tun.Name())

	// Configure TUN interface
	cmd := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tun.Name())
	if err := cmd.Run(); err != nil {
		log.Fatalf("[server] Failed to set TUN IP: %v", err)
	}
	cmd = exec.Command("ip", "link", "set", tun.Name(), "up")
	if err := cmd.Run(); err != nil {
		log.Fatalf("[server] Failed to bring TUN up: %v", err)
	}

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

	clients := make(map[string]*ClientSession)
	var clientMu sync.Mutex

	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("[server] Read error:", err)
			continue
		}

		clientMu.Lock()
		session, known := clients[clientAddr.String()]
		clientMu.Unlock()

		if !known {
			clientIP := assignClientIP(&clientMu, clients)
			if handleHandshake(conn, clientAddr, buf[:n], clientIP) {
				log.Println("[server] Handshake succeeded for", clientAddr)
				session = &ClientSession{
					Addr:     clientAddr,
					LastSeen: time.Now(),
					ClientIP: clientIP,
				}
				clientMu.Lock()
				clients[clientAddr.String()] = session
				clientMu.Unlock()

				go handleClientTraffic(conn, clientAddr, vpnCrypto, tun)
			} else {
				log.Println("[server] Handshake failed from", clientAddr)
				continue
			}
		}
	}
}

func assignClientIP(clientMu *sync.Mutex, clients map[string]*ClientSession) net.IP {
	clientMu.Lock()
	defer clientMu.Unlock()
	baseIP := net.ParseIP("10.0.0.0")
	lastOctet := len(clients) + 2 // Start at 10.0.0.2
	ip := make(net.IP, 4)
	copy(ip, baseIP.To4())
	ip[3] = byte(lastOctet)
	return ip
}

func handleClientTraffic(conn *net.UDPConn, clientAddr *net.UDPAddr, vpnCrypto *crypto.VPNCrypto, tun *water.Interface) {
	fmt.Println("[server] Handling traffic for", clientAddr)
	buf := make([]byte, 1500)

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil || addr.String() != clientAddr.String() {
			continue
		}

		decrypted, err := vpnCrypto.Decrypt(buf[:n])
		if err != nil {
			log.Println("[server] Decryption failed:", err)
			continue
		}

		fmt.Printf("[>] Decrypted %d bytes from %s: %x\n", len(decrypted), addr, decrypted)

		response, err := forwardToInternet(decrypted, tun)
		if err != nil {
			log.Println("[server] Forward error:", err)
			continue
		}

		encrypted, err := vpnCrypto.Encrypt(response)
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

func forwardToInternet(packet []byte, tun *water.Interface) ([]byte, error) {
	_, err := tun.Write(packet)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := tun.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func handleHandshake(conn *net.UDPConn, addr *net.UDPAddr, data []byte, clientIP net.IP) bool {
	if len(data) < 4+8+32 {
		log.Println("[server] Handshake too short")
		return false
	}

	r := bytes.NewReader(data)
	recvMagic := make([]byte, 4)
	r.Read(recvMagic)
	if !bytes.Equal(recvMagic, magic) {
		log.Println("[server] Invalid magic")
		return false
	}

	var ts int64
	binary.Read(r, binary.BigEndian, &ts)
	if math.Abs(float64(time.Now().Unix()-ts)) > 10 {
		log.Println("[server] Timestamp too far off")
		return false
	}

	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(recvMagic)
	binary.Write(mac, binary.BigEndian, ts)
	expectedHMAC := mac.Sum(nil)

	recvHMAC := make([]byte, 32)
	r.Read(recvHMAC)

	log.Printf("[server] Received handshake: magic=%x, ts=%d, hmac=%x", recvMagic, ts, recvHMAC)
	log.Printf("[server] Expected HMAC: %x", expectedHMAC)

	if !hmac.Equal(expectedHMAC, recvHMAC) {
		log.Println("[server] HMAC mismatch")
		return false
	}

	// Send handshake response with client IP
	response := bytes.NewBuffer(nil)
	response.Write(magic)
	binary.Write(response, binary.BigEndian, time.Now().Unix())
	response.Write(clientIP.To4())
	mac.Reset()
	mac.Write(response.Bytes())
	responseHMAC := mac.Sum(nil)
	response.Write(responseHMAC)

	log.Printf("[server] Sending response: magic=%x, ts=%d, ip=%v, hmac=%x, raw=%x", magic, time.Now().Unix(), clientIP, responseHMAC, response.Bytes())

	_, err := conn.WriteToUDP(response.Bytes(), addr)
	if err != nil {
		log.Println("[server] Handshake response failed:", err)
		return false
	}

	log.Println("[server] Client authenticated from", addr, "assigned IP", clientIP)
	return true
}
