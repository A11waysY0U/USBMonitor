package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// --- Protocol constants (must match client) ---
const (
	ProtocolPort   = 9443
	HeaderSize     = 8
	MaxPayloadSize = 1024 * 1024
)

const (
	MsgHeartbeat uint32 = 0x0001
	MsgData      uint32 = 0x0002
	MsgCommand   uint32 = 0x0003
	MsgResponse  uint32 = 0x0004
)

type Message struct {
	Type   uint32
	Length uint32
	Data   []byte
}

// --- TLS certificate generation (self-signed, for dev/testing) ---
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"USBMonitor Dev"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

func loadOrGenerateCert(certFile, keyFile string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			log.Printf("[INFO] 已加载证书: %s / %s", certFile, keyFile)
			return cert, nil
		}
		log.Printf("[WARN] 无法加载证书文件 (%v)，将自动生成自签名证书", err)
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return tls.Certificate{}, err
	}
	log.Println("[INFO] 已生成自签名证书（开发模式）")
	return cert, nil
}

// --- Protocol reader ---
func readMessage(r io.Reader) (*Message, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	msg := &Message{
		Type:   binary.BigEndian.Uint32(header[0:4]),
		Length: binary.BigEndian.Uint32(header[4:8]),
	}

	if msg.Length > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d (max %d)", msg.Length, MaxPayloadSize)
	}

	if msg.Length > 0 {
		msg.Data = make([]byte, msg.Length)
		if _, err := io.ReadFull(r, msg.Data); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return msg, nil
}

func writeMessage(w io.Writer, msgType uint32, data []byte) error {
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(header[0:4], msgType)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(data)))

	buf := append(header, data...)
	_, err := w.Write(buf)
	return err
}

// --- Client handler ---
type ClientID uint64

type Server struct {
	mu      sync.Mutex
	clients map[ClientID]net.Conn
	nextID  ClientID
}

func NewServer() *Server {
	return &Server{
		clients: make(map[ClientID]net.Conn),
	}
}

func (s *Server) addClient(conn net.Conn) ClientID {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := s.nextID
	s.clients[id] = conn
	return id
}

func (s *Server) removeClient(id ClientID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	clientID := s.addClient(conn)
	defer s.removeClient(clientID)

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[CONNECT] 客户端 #%d 已连接: %s", clientID, remoteAddr)

	conn.SetDeadline(time.Time{})

	go s.heartbeatLoop(conn, clientID)

	for {
		msg, err := readMessage(conn)
		if err != nil {
			if err == io.EOF {
				log.Printf("[DISCONNECT] 客户端 #%d 正常断开: %s", clientID, remoteAddr)
			} else {
				log.Printf("[DISCONNECT] 客户端 #%d 读取错误: %v", clientID, err)
			}
			return
		}

		s.dispatch(clientID, conn, msg)
	}
}

func (s *Server) heartbeatLoop(conn net.Conn, clientID ClientID) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := writeMessage(conn, MsgHeartbeat, nil); err != nil {
			log.Printf("[HEARTBEAT] 客户端 #%d 心跳发送失败: %v", clientID, err)
			conn.Close()
			return
		}
		log.Printf("[HEARTBEAT] -> 客户端 #%d", clientID)
	}
}

func (s *Server) dispatch(clientID ClientID, conn net.Conn, msg *Message) {
	switch msg.Type {
	case MsgHeartbeat:
		log.Printf("[HEARTBEAT] <- 客户端 #%d", clientID)

	case MsgData:
		log.Printf("[DATA] 客户端 #%d: %d bytes", clientID, len(msg.Data))
		if len(msg.Data) > 0 {
			log.Printf("[DATA] 客户端 #%d: %s", clientID, string(msg.Data))
		} else {
			log.Printf("[DATA] 客户端 #%d: (empty)", clientID)
		}
		writeMessage(conn, MsgResponse, []byte("ACK"))

	case MsgCommand:
		cmd := string(msg.Data)
		log.Printf("[CMD] 客户端 #%d: %s", clientID, cmd)
		response := fmt.Sprintf("OK: %s", cmd)
		writeMessage(conn, MsgResponse, []byte(response))

	case MsgResponse:
		log.Printf("[RESP] 客户端 #%d: %s", clientID, string(msg.Data))

	default:
		log.Printf("[UNKNOWN] 客户端 #%d: type=0x%04X", clientID, msg.Type)
		writeMessage(conn, MsgResponse, []byte("UNKNOWN_MSG_TYPE"))
	}
}

// --- Main ---
func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("=== USBMonitor TLS Server (Go) ===")

	cert, err := loadOrGenerateCert(
		os.Getenv("TLS_CERT_FILE"),
		os.Getenv("TLS_KEY_FILE"),
	)
	if err != nil {
		log.Fatalf("[FATAL] 证书加载失败: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf(":%d", ProtocolPort)
	if envPort := os.Getenv("LISTEN_PORT"); envPort != "" {
		addr = fmt.Sprintf(":%s", envPort)
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		log.Fatalf("[FATAL] 监听失败 %s: %v", addr, err)
	}
	defer listener.Close()

	log.Printf("[LISTEN] 服务已启动: %s (TLS)", addr)

	srv := NewServer()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		<-sigCh
		log.Println("[SHUTDOWN] 收到退出信号，正在关闭...")
		close(done)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				log.Println("[SHUTDOWN] 服务已停止")
				return
			default:
				log.Printf("[ERROR] Accept 错误: %v", err)
				continue
			}
		}

		go srv.handleClient(conn)
	}
}
