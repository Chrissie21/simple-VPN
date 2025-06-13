package main

import (
	"bytes"
	"crypto/rsa"
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

var (
	serverPrivKey *rsa.PrivateKey
	clientPubKey  *rsa.PublicKey
	magic         = []byte("VPN1")
)

type TrafficStats struct {
	StartTime time.Time
	BytesIn   int
	BytesOut  int
}

type ClientSession struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
	ClientIP net.IP
	Traffic  TrafficStats
}

var clients = make(map[string]*ClientSession)

// Load RSA keys
func init() {
	var err error
	serverPrivKey, err = crypto.LoadPrivateKey("server_private.pem")
	if err != nil {
		log.Fatalf("[server] Load server private key: %v", err)
	}
	pub, err := crypto.LoadPublicKey("client_public.pem")
	if err != nil {
		log.Fatalf("[server] Load client public key: %v", err)
	}
	clientPubKey = pub
}

func main() {
	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("[server] Failed to create TUN: %v", err)
	}
	fmt.Printf("[server] TUN %s created\n", tun.Name())

	exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tun.Name()).Run()
	exec.Command("ip", "link", "set", tun.Name(), "up").Run()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 8080})
	if err != nil {
		log.Fatalf("[server] UDP listen error: %v", err)
	}
	defer conn.Close()
	fmt.Println("[server] Listening on UDP :8080")

	vpnCrypto, err := crypto.NewVPNCrypto([]byte("0123456789ABCDEF0123456789ABCDEF"))
	if err != nil {
		log.Fatalf("[server] Crypto init error: %v", err)
	}

	clients := make(map[string]*ClientSession)
	var mu sync.Mutex

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("[server] Read error:", err)
			continue
		}

		mu.Lock()
		session, known := clients[addr.String()]
		mu.Unlock()

		if !known {
			ip := assignClientIP(&mu, clients)
			if handleHandshake(conn, addr, buf[:n], ip) {
				session = &ClientSession{
					Addr:     addr,
					LastSeen: time.Now(),
					ClientIP: ip,
					Traffic:  TrafficStats{StartTime: time.Now()},
				}
				mu.Lock()
				clients[addr.String()] = session
				mu.Unlock()
				go handleClientTraffic(conn, vpnCrypto, tun, session, &mu)
				log.Println("[server] Handshake succeeded for", addr)
			} else {
				log.Println("[server] Handshake failed for", addr)
			}
		}
	}
}

func assignClientIP(mu *sync.Mutex, clients map[string]*ClientSession) net.IP {
	mu.Lock()
	defer mu.Unlock()
	base := net.ParseIP("10.0.0.0").To4()
	ip := make(net.IP, len(base))
	copy(ip, base)
	ip[3] = byte(len(clients) + 2)
	return ip
}

func handleHandshake(conn *net.UDPConn, addr *net.UDPAddr, data []byte, clientIP net.IP) bool {
	if len(data) < 4+8+256 {
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
		log.Println("[server] Timestamp invalid:", ts)
		return false
	}

	sig := make([]byte, 256)
	r.Read(sig)
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(ts))
	if err := crypto.VerifySignature(clientPubKey, tsBytes, sig); err != nil {
		log.Println("[server] Signature verification failed:", err)
		return false
	}

	resp := bytes.NewBuffer(nil)
	resp.Write(magic)
	binary.Write(resp, binary.BigEndian, time.Now().Unix())
	resp.Write(clientIP.To4())
	challenge := resp.Bytes()
	sig2, _ := crypto.SignData(serverPrivKey, challenge)
	resp.Write(sig2)

	if _, err := conn.WriteToUDP(resp.Bytes(), addr); err != nil {
		log.Println("[server] Handshake response failed:", err)
		return false
	}
	log.Printf("[server] Client %s assigned IP %v\n", addr, clientIP)
	return true
}

func handleClientTraffic(conn *net.UDPConn, vpnCrypto *crypto.VPNCrypto, tun *water.Interface, session *ClientSession, mu *sync.Mutex) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil || addr.String() != session.Addr.String() {
			continue
		}
		session.LastSeen = time.Now()
		decrypted, err := vpnCrypto.Decrypt(buf[:n])
		if err != nil {
			log.Println("[server] Decrypt error:", err)
			continue
		}
		session.Traffic.BytesIn += len(decrypted)

		_, err = tun.Write(decrypted)
		if err != nil {
			log.Println("[server] TUN write error:", err)
			break
		}

		respBuf := make([]byte, 1500)
		m, err := tun.Read(respBuf)
		if err != nil {
			log.Println("[server] TUN read error:", err)
			break
		}

		encrypted, err := vpnCrypto.Encrypt(respBuf[:m])
		if err != nil {
			log.Println("[server] Encrypt error:", err)
			break
		}
		session.Traffic.BytesOut += len(encrypted)
		conn.WriteToUDP(encrypted, session.Addr)
	}

	duration := time.Since(session.Traffic.StartTime)
	log.Printf("[metrics] %s disconnected after %s, in=%d bytes, out=%d bytes",
		session.Addr, duration, session.Traffic.BytesIn, session.Traffic.BytesOut)

	mu.Lock()
	delete(clients, session.Addr.String())
	mu.Unlock()
}
