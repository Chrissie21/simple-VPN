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
	"time"

	"github.com/Chrissie21/myproject/crypto"
	"github.com/songgao/water"
)

var (
	magic         = []byte("VPN1")
	clientPrivKey *rsa.PrivateKey
	serverPubKey  *rsa.PublicKey
)

func init() {
	var err error
	clientPrivKey, err = crypto.LoadPrivateKey("client_private.pem")
	if err != nil {
		log.Fatalf("[client] Load private key: %v", err)
	}
	pub, err := crypto.LoadPublicKey("server_public.pem")
	if err != nil {
		log.Fatalf("[client] Load server public key: %v", err)
	}
	serverPubKey = pub
}

func main() {
	iface, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatalf("[client] TUN creation failed: %v", err)
	}
	fmt.Printf("[client] TUN %s created\n", iface.Name())

	conn, err := net.Dial("udp", "10.211.55.7:8080")
	if err != nil {
		log.Fatalf("[client] UDP connect failed: %v", err)
	}
	defer conn.Close()

	clientIP, err := sendHandshake(conn)
	if err != nil {
		log.Fatalf("[client] Handshake failed: %v", err)
	}

	exec.Command("ifconfig", iface.Name(), clientIP.String(), "10.0.0.1", "netmask", "255.255.255.0", "up").Run()

	vpnCrypto, _ := crypto.NewVPNCrypto([]byte("0123456789ABCDEF0123456789ABCDEF"))
	fmt.Println("[client] Connected to VPN, assigned IP", clientIP)

	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Println("[client] Read error:", err)
				continue
			}
			decrypted, err := vpnCrypto.Decrypt(buf[:n])
			if err != nil {
				log.Println("[client] Decrypt error:", err)
				continue
			}
			iface.Write(decrypted)
		}
	}()

	buf := make([]byte, 1500)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Println("[client] TUN read error:", err)
			continue
		}
		encrypted, err := vpnCrypto.Encrypt(buf[:n])
		if err != nil {
			log.Println("[client] Encrypt error:", err)
			continue
		}
		conn.Write(encrypted)
	}
}

func sendHandshake(conn net.Conn) (net.IP, error) {
	ts := time.Now().Unix()
	buf := bytes.NewBuffer(nil)
	buf.Write(magic)
	buf.Write(make([]byte, 8))
	binary.BigEndian.PutUint64(buf.Bytes()[4:], uint64(ts))

	sig, _ := crypto.SignData(clientPrivKey, buf.Bytes()[4:12])
	buf.Write(sig)

	conn.Write(buf.Bytes())

	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(resp[:n])
	recvMagic := make([]byte, 4)
	r.Read(recvMagic)
	if !bytes.Equal(recvMagic, magic) {
		return nil, fmt.Errorf("bad magic: %x", recvMagic)
	}

	var ts2 int64
	binary.Read(r, binary.BigEndian, &ts2)
	if math.Abs(float64(time.Now().Unix()-ts2)) > 10 {
		return nil, fmt.Errorf("timestamp out of sync")
	}

	ipBytes := make([]byte, 4)
	r.Read(ipBytes)
	challenge := resp[:4+8+4]
	sig2 := make([]byte, 256)
	r.Read(sig2)
	if err := crypto.VerifySignature(serverPubKey, challenge, sig2); err != nil {
		return nil, fmt.Errorf("server signature invalid: %v", err)
	}

	return net.IP(ipBytes), nil
}
