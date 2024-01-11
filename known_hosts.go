package soh

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"syscall"
)

type KnownHosts map[string][]*x509.Certificate

func (kh KnownHosts) Knows(hostname string) bool {
	if len(kh) == 0 {
		return false
	}
	_, ok := kh[hostname]
	return ok
}

type InvalidKnownHost struct {
	line string
}

func (e InvalidKnownHost) Error() string {
	return fmt.Sprintf("invalid known host line: %s", e.line)
}

func ParseKnownHosts(filename string) (knownHosts KnownHosts, invalidLines []int, err error) {
	knownHosts = make(map[string][]*x509.Certificate)
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		// the known hosts file simply does not exist yet, so there is no known host
		return knownHosts, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(file)

	for i := 0; scanner.Scan(); i++ {
		knownHost := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(knownHost)
		if len(fields) != 3 || fields[1] != "x509-certificate" {
			invalidLines = append(invalidLines, i)
			continue
		}
		certBytes, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		certs := knownHosts[fields[0]]
		certs = append(certs, cert)
		knownHosts[fields[0]] = certs
	}
	return knownHosts, invalidLines, nil
}

func AppendKnownHost(filename string, host string, cert *x509.Certificate) error {
	encodedCert := base64.StdEncoding.EncodeToString(cert.Raw)
	knownHosts, err := os.OpenFile(filename, os.O_CREATE|syscall.O_APPEND|syscall.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = knownHosts.WriteString(fmt.Sprintf("%s x509-certificate %s\n", host, encodedCert))
	if err != nil {
		return err
	}

	return nil
}
