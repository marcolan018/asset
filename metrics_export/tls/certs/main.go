package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"time"
)

var (
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	hosts             = []string{"victoriametrics"}
)

func main() {
	key, cert, err := createCACertificate("ca", nil)
	if err != nil {
		log.Printf("Failed to create CA: %v", err)
	}
	certPEM, _ := pemEncode(cert, key)
	log.Println("ca cert:")
	log.Println(base64.StdEncoding.EncodeToString(certPEM.Bytes()))
	//log.Println(string(keyPEM.Bytes()))
	caKey, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil {
		log.Printf("Failed to parse ca key")
	}
	caCerts, err := x509.ParseCertificates(cert)
	if err != nil {
		log.Printf("Failed to parse ca certs")
	}
	caCert := caCerts[0]

	s_key, s_cert, err := createCertificate(true, "server", nil, hosts, nil, caCert, caKey, nil)
	if err != nil {
		log.Printf("Failed to server certs: %v", err)
	}
	s_certPEM, s_keyPEM := pemEncode(s_cert, s_key)
	log.Println("server cert:")
	log.Println(base64.StdEncoding.EncodeToString(s_certPEM.Bytes()))
	log.Println("server key:")
	log.Println(base64.StdEncoding.EncodeToString(s_keyPEM.Bytes()))

	c_key, c_cert, err := createCertificate(true, "client", nil, hosts, nil, caCert, caKey, nil)
	if err != nil {
		log.Printf("Failed to client certs: %v", err)
	}
	c_scertPEM, c_keyPEM := pemEncode(c_cert, c_key)
	log.Println("client cert:")
	log.Println(base64.StdEncoding.EncodeToString(c_scertPEM.Bytes()))
	log.Println("client key:")
	log.Println(base64.StdEncoding.EncodeToString(c_keyPEM.Bytes()))
}

func createCACertificate(cn string, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	sn, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %v", err)
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"Red Hat, Inc."},
			Country:      []string{"US"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour * 5),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if caKey == nil {
		caKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key")
			return nil, nil, err
		}
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create certificate")
		return nil, nil, err
	}
	caKeyBytes := x509.MarshalPKCS1PrivateKey(caKey)
	return caKeyBytes, caBytes, nil
}

func createCertificate(isServer bool, cn string, ou []string, dns []string, ips []net.IP,
	caCert *x509.Certificate, caKey *rsa.PrivateKey, key *rsa.PrivateKey) ([]byte, []byte, error) {
	sn, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number")
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Organization: []string{"Red Hat, Inc."},
			Country:      []string{"US"},
			CommonName:   cn,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * 365 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if !isServer {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if ou != nil {
		cert.Subject.OrganizationalUnit = ou
	}
	if dns != nil {
		dns = append(dns[:1], dns[0:]...)
		dns[0] = cn
		cert.DNSNames = dns
	} else {
		cert.DNSNames = []string{cn}
	}
	if ips != nil {
		cert.IPAddresses = ips
	}

	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key")
			return nil, nil, err
		}
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create certificate")
		return nil, nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return keyBytes, caBytes, nil
}

func pemEncode(cert []byte, key []byte) (*bytes.Buffer, *bytes.Buffer) {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		log.Fatalf("Failed to encode cert")
	}

	keyPEM := new(bytes.Buffer)
	err = pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: key,
	})
	if err != nil {
		log.Fatalf("Failed to encode key")
	}

	return certPEM, keyPEM
}
