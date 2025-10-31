package gmtls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	gmX509 "github.com/tjfoc/gmsm/x509"
)

type Certificate = tls.Certificate

type ClientAuthType = tls.ClientAuthType

const (
	NoClientCert               = tls.NoClientCert
	RequestClientCert          = tls.RequestClientCert
	RequireAnyClientCert       = tls.RequireAnyClientCert
	VerifyClientCertIfGiven    = tls.VerifyClientCertIfGiven
	RequireAndVerifyClientCert = tls.RequireAndVerifyClientCert
)

const (
	VersionGMSSL                 = tls.VersionTLS12
	GMTLS_SM2_WITH_SM4_SM3       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	GMTLS_ECDHE_SM2_WITH_SM4_SM3 = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
)

type GMSupport struct{}

type Config struct {
	Certificates       []Certificate
	ClientAuth         ClientAuthType
	ClientCAs          *gmX509.CertPool
	RootCAs            *gmX509.CertPool
	InsecureSkipVerify bool
	ServerName         string
	CipherSuites       []uint16
	MinVersion         uint16
	MaxVersion         uint16
	GMSupport          *GMSupport
	HandshakeTimeout   time.Duration
}

func (c *Config) toTLSConfig() *tls.Config {
	if c == nil {
		return &tls.Config{}
	}

	conf := &tls.Config{
		Certificates:       c.Certificates,
		ClientAuth:         c.ClientAuth,
		InsecureSkipVerify: c.InsecureSkipVerify,
		ServerName:         c.ServerName,
	}

	if c.ClientCAs != nil {
		conf.ClientCAs = c.ClientCAs.CertPool
	}
	if c.RootCAs != nil {
		conf.RootCAs = c.RootCAs.CertPool
	}
	if len(c.CipherSuites) > 0 {
		suites := make([]uint16, len(c.CipherSuites))
		copy(suites, c.CipherSuites)
		conf.CipherSuites = suites
	}
	if c.MinVersion != 0 {
		conf.MinVersion = c.MinVersion
	}
	if c.MaxVersion != 0 {
		conf.MaxVersion = c.MaxVersion
	}
	return conf
}

type Conn struct {
	*tls.Conn
	handshakeDeadline time.Time
}

func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(&net.Dialer{}, network, addr, config)
}

func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	tlsConf := config.toTLSConfig()
	tlsConn, err := tls.DialWithDialer(dialer, network, addr, tlsConf)
	if err != nil {
		return nil, err
	}
	conn := &Conn{Conn: tlsConn}
	if config != nil && config.HandshakeTimeout > 0 {
		deadline := time.Now().Add(config.HandshakeTimeout)
		conn.handshakeDeadline = deadline
		tlsConn.SetDeadline(deadline)
	}
	return conn, nil
}

func Server(conn net.Conn, config *Config) *Conn {
	tlsConf := config.toTLSConfig()
	tlsConn := tls.Server(conn, tlsConf)
	wrapped := &Conn{Conn: tlsConn}
	if config != nil && config.HandshakeTimeout > 0 {
		deadline := time.Now().Add(config.HandshakeTimeout)
		wrapped.handshakeDeadline = deadline
		tlsConn.SetDeadline(deadline)
	}
	return wrapped
}

func (c *Conn) Handshake() error {
	if c == nil {
		return nil
	}
	err := c.Conn.Handshake()
	if err != nil {
		return err
	}
	if !c.handshakeDeadline.IsZero() {
		c.Conn.SetDeadline(time.Time{})
	}
	return nil
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState()
}

func (c *Conn) VerifyHostname(host string) error {
	return c.Conn.VerifyHostname(host)
}

func (c *Conn) TLSConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState()
}

func (c *Conn) Certificates() []*x509.Certificate {
	state := c.Conn.ConnectionState()
	return state.PeerCertificates
}

func (c *Conn) CloseWrite() error {
	return c.Conn.CloseWrite()
}
