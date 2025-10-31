package transproxy

import (
	"testing"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
)

func TestParsePortList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "443", []uint16{443}, false},
		{"withSpaces", " 443 , 8443 ", []uint16{443, 8443}, false},
		{"duplicates", "443,443,8443", []uint16{443, 8443}, false},
		{"invalid", "a", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePortList() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParsePortList() got length %d, want %d", len(got), len(tt.want))
			}
			for i, port := range got {
				if port != tt.want[i] {
					t.Fatalf("ParsePortList()[%d] = %d, want %d", i, port, tt.want[i])
				}
			}
		})
	}
}

func TestGMSSLProxyShouldEncrypt(t *testing.T) {
	proxy := &GMSSLProxy{}
	proxy.portSet = map[uint16]struct{}{
		443:  {},
		8443: {},
	}

	if !proxy.shouldEncrypt(443) {
		t.Fatalf("shouldEncrypt(443) = false, want true")
	}
	if proxy.shouldEncrypt(80) {
		t.Fatalf("shouldEncrypt(80) = true, want false")
	}
}

func TestGMSSLProxyCloneClientConfig(t *testing.T) {
	cfg := &gmtls.Config{ServerName: "old", HandshakeTimeout: time.Second}
	proxy := &GMSSLProxy{clientTLSConfig: cfg}

	cloned := proxy.cloneClientConfig("example.org")
	if cloned == nil {
		t.Fatalf("cloneClientConfig() returned nil")
	}
	if cloned.ServerName != "example.org" {
		t.Fatalf("cloneClientConfig() ServerName = %s, want example.org", cloned.ServerName)
	}
	if cloned == cfg {
		t.Fatalf("cloneClientConfig() returned original pointer")
	}
	if cloned.HandshakeTimeout != time.Second {
		t.Fatalf("cloneClientConfig() HandshakeTimeout = %s, want %s", cloned.HandshakeTimeout, time.Second)
	}
}

func TestGMSSLProxyIsLocalIP(t *testing.T) {
	proxy := &GMSSLProxy{}
	proxy.localIPs = map[string]struct{}{
		"10.0.0.1": {},
	}

	if !proxy.isLocalIP("127.0.0.1") {
		t.Fatalf("isLocalIP(loopback) = false, want true")
	}
	if !proxy.isLocalIP("10.0.0.1") {
		t.Fatalf("isLocalIP(10.0.0.1) = false, want true")
	}
	if proxy.isLocalIP("203.0.113.10") {
		t.Fatalf("isLocalIP(203.0.113.10) = true, want false")
	}
}
