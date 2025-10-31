package transproxy

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

type GMSSLProxy struct {
	GMSSLProxyConfig

	clientTLSConfig *gmtls.Config
	serverTLSConfig *gmtls.Config
	portSet         map[uint16]struct{}
	localIPs        map[string]struct{}
	mu              sync.RWMutex
}

type GMSSLProxyConfig struct {
	Enabled          bool
	ListenAddress    string
	Ports            []uint16
	CertificateFile  string
	KeyFile          string
	CACertFile       string
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
}

func NewGMSSLProxy(c GMSSLProxyConfig) (*GMSSLProxy, error) {
	proxy := &GMSSLProxy{
		GMSSLProxyConfig: c,
		portSet:          make(map[uint16]struct{}),
	}

	for _, port := range c.Ports {
		proxy.portSet[port] = struct{}{}
	}

	if err := proxy.refreshLocalIPs(); err != nil {
		return nil, err
	}

	if !c.Enabled {
		return proxy, nil
	}

	if c.ListenAddress == "" {
		return nil, errors.New("gmssl listen address is required when enabled")
	}

	if c.CertificateFile == "" || c.KeyFile == "" || c.CACertFile == "" {
		return nil, errors.New("gmssl certificate, key and ca files are required when gmssl is enabled")
	}

	if c.DialTimeout == 0 {
		proxy.DialTimeout = 10 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		proxy.HandshakeTimeout = 10 * time.Second
	}

	if err := proxy.loadTLSConfig(); err != nil {
		return nil, err
	}

	return proxy, nil
}

func (p *GMSSLProxy) loadTLSConfig() error {
	cert, err := gmtls.LoadX509KeyPair(p.CertificateFile, p.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load gmssl certificate: %w", err)
	}

	caBytes, err := ioutil.ReadFile(p.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to load gmssl ca certificate: %w", err)
	}

	caPool := gmx509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caBytes); !ok {
		return errors.New("failed to parse gmssl ca certificate")
	}

	clientConfig := &gmtls.Config{
		Certificates: []gmtls.Certificate{cert},
		RootCAs:      caPool,
		GMSupport:    &gmtls.GMSupport{},
		CipherSuites: []uint16{
			gmtls.GMTLS_SM2_WITH_SM4_SM3,
			gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
		},
		MinVersion:       gmtls.VersionGMSSL,
		MaxVersion:       gmtls.VersionGMSSL,
		HandshakeTimeout: p.HandshakeTimeout,
	}

	serverConfig := &gmtls.Config{
		Certificates: []gmtls.Certificate{cert},
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		RootCAs:      caPool,
		GMSupport:    &gmtls.GMSupport{},
		CipherSuites: []uint16{
			gmtls.GMTLS_SM2_WITH_SM4_SM3,
			gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
		},
		MinVersion:       gmtls.VersionGMSSL,
		MaxVersion:       gmtls.VersionGMSSL,
		HandshakeTimeout: p.HandshakeTimeout,
	}

	p.clientTLSConfig = clientConfig
	p.serverTLSConfig = serverConfig
	return nil
}

func (p *GMSSLProxy) Start() error {
	if !p.Enabled {
		log.Printf("info: GMSSL proxy disabled")
		return nil
	}

	log.Printf("info: Start listener on %s category='GMSSL-Proxy'", p.ListenAddress)

	go func() {
		ListenTCP(p.ListenAddress, func(tc *TCPConn) {
			p.handleConnection(tc)
		})
	}()

	return nil
}

func (p *GMSSLProxy) handleConnection(tc *TCPConn) {
	destHost, destPortStr, err := net.SplitHostPort(tc.OrigAddr)
	if err != nil {
		log.Printf("error: GMSSL proxy failed to parse original address: %s", err)
		return
	}

	portValue, err := strconv.ParseUint(destPortStr, 10, 16)
	if err != nil {
		log.Printf("error: GMSSL proxy failed to parse destination port: %s", err)
		return
	}
	destPort := uint16(portValue)

	if !p.shouldEncrypt(destPort) {
		log.Printf("debug: GMSSL proxy forwarding without encryption for port %d", destPort)
		p.forwardPlain(tc)
		return
	}

	remoteHost, _, err := net.SplitHostPort(tc.RemoteAddr().String())
	if err != nil {
		log.Printf("error: GMSSL proxy failed to parse remote address: %s", err)
		return
	}

	if p.isLocalIP(remoteHost) {
		log.Printf("debug: GMSSL proxy handling outbound connection to %s", tc.OrigAddr)
		p.forwardAsClient(tc, destHost)
	} else {
		log.Printf("debug: GMSSL proxy handling inbound GMSSL connection from %s", remoteHost)
		p.forwardAsServer(tc)
	}
}

func (p *GMSSLProxy) forwardPlain(tc *TCPConn) {
	dialer := &net.Dialer{Timeout: p.DialTimeout}
	destConn, err := dialer.Dial("tcp", tc.OrigAddr)
	if err != nil {
		log.Printf("error: GMSSL proxy failed to connect to destination: %s", err)
		return
	}
	Pipe(tc, destConn)
}

func (p *GMSSLProxy) forwardAsClient(tc *TCPConn, serverName string) {
	cfg := p.cloneClientConfig(serverName)
	dialer := &net.Dialer{Timeout: p.DialTimeout, KeepAlive: 3 * time.Minute}
	conn, err := gmtls.DialWithDialer(dialer, "tcp", tc.OrigAddr, cfg)
	if err != nil {
		log.Printf("error: GMSSL proxy failed to establish GMSSL client connection: %s", err)
		return
	}
	Pipe(tc, conn)
}

func (p *GMSSLProxy) forwardAsServer(tc *TCPConn) {
	conn := gmtls.Server(tc.TCPConn, p.serverTLSConfig)
	if err := conn.Handshake(); err != nil {
		log.Printf("error: GMSSL proxy failed during GMSSL handshake: %s", err)
		return
	}

	dialer := &net.Dialer{Timeout: p.DialTimeout}
	destConn, err := dialer.Dial("tcp", tc.OrigAddr)
	if err != nil {
		log.Printf("error: GMSSL proxy failed to reach local destination after handshake: %s", err)
		return
	}

	PipeBidirectional(conn, destConn)
}

func (p *GMSSLProxy) shouldEncrypt(port uint16) bool {
	if len(p.portSet) == 0 {
		return false
	}
	_, ok := p.portSet[port]
	return ok
}

func (p *GMSSLProxy) cloneClientConfig(serverName string) *gmtls.Config {
	if p.clientTLSConfig == nil {
		return nil
	}
	cfg := *p.clientTLSConfig
	cfg.ServerName = serverName
	return &cfg
}

func (p *GMSSLProxy) refreshLocalIPs() error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("failed to enumerate local addresses: %w", err)
	}

	set := make(map[string]struct{})
	set["127.0.0.1"] = struct{}{}
	set["::1"] = struct{}{}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip == nil {
			continue
		}
		set[ip.String()] = struct{}{}
	}

	p.mu.Lock()
	p.localIPs = set
	p.mu.Unlock()
	return nil
}

func (p *GMSSLProxy) isLocalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.IsLoopback() {
		return true
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.localIPs[ip]
	return ok
}

func ParsePortList(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parts := strings.Split(value, ",")
	ports := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{})

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		p64, err := strconv.ParseUint(trimmed, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s': %w", trimmed, err)
		}
		port := uint16(p64)
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	return ports, nil
}
