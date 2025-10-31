package x509

import "crypto/x509"

type CertPool struct {
	*x509.CertPool
}

func NewCertPool() *CertPool {
	return &CertPool{CertPool: x509.NewCertPool()}
}
