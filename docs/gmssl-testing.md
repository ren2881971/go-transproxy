# GMSSL Transparent Proxy Testing Guide

The GMSSL proxy integrates mutual authentication, SM2/SM3/SM4 cipher suites, and selective port encryption. This guide explains how to exercise those capabilities end-to-end.

## Prerequisites

* Linux host with root access (iptables rules are required for transparent proxying).
* A working installation of [GmSSL](https://github.com/guanzhi/GmSSL) that provides the `gmssl` command-line utility.
* Go 1.18 or newer.
* Optional: a backend HTTPS service that you want to protect. The examples use a simple Go HTTPS echo server.

## 1. Build and unit test the proxy

```bash
go test -vet=off ./...
go build ./...
```

Running the test suite validates helper logic (port filtering, local IP detection, TLS config cloning, etc.). The build step confirms that the GMSSL-specific code and vendored dependencies compile.

## 2. Generate SM2 certificates with GmSSL

Create a working directory for test material:

```bash
mkdir -p ./tmp/certs
cd ./tmp/certs
```

Generate a root CA, then issue server and client certificates. The commands below use the GmSSL `certgen`/`certsign` helpers; adjust the subject fields to match your environment.

```bash
# Root CA (SM2 key pair)
gmssl certgen -C CN -ST Beijing -L Beijing -O Example -OU Lab -CN "GMSSL Test CA" \
  -days 365 -keyout ca.key -out ca.crt -alg sm2 -selfsign

# Server certificate signed by the CA
gmssl certgen -C CN -ST Beijing -L Beijing -O Example -OU Lab -CN "backend.example" \
  -days 365 -keyout server.key -out server.csr -alg sm2
gmssl certsign -in server.csr -signkey ca.key -signcert ca.crt -out server.crt

# Client certificate signed by the CA
gmssl certgen -C CN -ST Beijing -L Beijing -O Example -OU Lab -CN "client.example" \
  -days 365 -keyout client.key -out client.csr -alg sm2
gmssl certsign -in client.csr -signkey ca.key -signcert ca.crt -out client.crt
```

Return to the repository root when you finish:

```bash
cd ../../
```

## 3. Launch a local HTTPS target (optional)

For outbound testing, start a simple GMSSL server that presents the server certificate you just created. The `gmssl` CLI offers an `s_server` helper:

```bash
gmssl s_server -accept 9443 \
  -cert ./tmp/certs/server.crt \
  -key ./tmp/certs/server.key \
  -CAfile ./tmp/certs/ca.crt \
  -Verify 1
```

You can substitute any other GMSSL-capable service that terminates on one of the protected ports.

## 4. Start the GMSSL transparent proxy

Run `transproxy` with GMSSL enabled. Replace the certificate paths with the ones you generated. You need root privileges if you want it to install iptables rules automatically.

```bash
sudo -E ./transproxy \
  -gmssl-enable \
  -gmssl-listen :3134 \
  -gmssl-ports 443,8443,9443 \
  -gmssl-cert ./tmp/certs/server.crt \
  -gmssl-key ./tmp/certs/server.key \
  -gmssl-ca ./tmp/certs/ca.crt \
  -private-dns 192.168.0.100 \
  -public-dns 8.8.8.8
```

Key points:

* Only traffic destined to the ports listed in `-gmssl-ports` is upgraded to GMSSL.
* The same certificate/key pair is used for both client and server mutual authentication in this demo. In production, provide role-specific certificates if required.

## 5. Exercise inbound GMSSL traffic

From another host (or a network namespace that reaches the proxy), initiate a GMSSL client handshake targeting the proxy listener. Use the client certificate that chains back to your CA:

```bash
gmssl s_client -connect <proxy_ip>:3134 \
  -cert ./tmp/certs/client.crt \
  -key ./tmp/certs/client.key \
  -CAfile ./tmp/certs/ca.crt \
  -servername backend.example
```

The connection should succeed only when the client presents a certificate signed by `ca.crt`. Inspect the `transproxy` logs to confirm the GMSSL handshake and the subsequent forwarding to the original destination.

## 6. Exercise outbound GMSSL traffic

Configure an application behind the proxy (for example, by running it on the same machine) to connect to a remote GMSSL service on one of the filtered ports (e.g., `9443`). The proxy should automatically establish a GMSSL session on behalf of the application using the configured certificates.

You can verify the mutual-authentication behaviour by attempting the same request without the proxy— the handshake will fail if the remote service requires a client certificate and the application does not provide one.

## 7. Tear down

Stop `transproxy` with `Ctrl+C`. If iptables rules were installed, the proxy automatically removes them during shutdown. Delete the temporary certificates when you no longer need them.

---

Following the steps above gives you confidence that:

* The selective port filter is in effect.
* Mutual certificate authentication works for both inbound and outbound flows.
* SM2/SM3/SM4 cipher suites negotiated through GmSSL are functioning with the transparent proxy.
