package node

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/file"
	"github.com/wyx2685/v2node/common/task"
)

func (c *Controller) renewCertTask() error {
	l, err := NewLego(c.info.Common.CertInfo)
	if err != nil {
		log.WithField("tag", c.tag).Info("new lego error: ", err)
		return nil
	}
	err = l.RenewCert()
	if err != nil {
		log.WithField("tag", c.tag).Info("renew cert error: ", err)
		return nil
	}
	return nil
}

func (c *Controller) syncOnlineCertTask() error {
	cert := c.info.Common.CertInfo
	certPEM, keyPEM, changed, err := c.fetchOnlineCertPair()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("sync online cert error")
		return nil
	}
	if !changed {
		return nil
	}
	currentCert, currentKey, err := loadCertPair(cert.CertFile, cert.KeyFile)
	if err == nil && bytes.Equal(currentCert, certPEM) && bytes.Equal(currentKey, keyPEM) {
		return nil
	}
	if err := writeCertPair(cert.CertFile, cert.KeyFile, certPEM, keyPEM); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("write online cert error")
		return nil
	}
	log.WithField("tag", c.tag).Info("Online cert updated")
	return nil
}

func (c *Controller) startCertTask(node *panel.NodeInfo) {
	if node.Security != panel.Tls {
		return
	}
	switch c.info.Common.CertInfo.CertMode {
	case "none", "", "file", "self":
	case "dns", "http":
		c.renewCertPeriodic = &task.Task{
			Name:     "renewCertTask",
			Interval: time.Hour * 24,
			Execute:  c.renewCertTask,
			Reload:   c.reloadTask,
		}
		log.WithField("tag", c.tag).Info("Start renew cert")
		_ = c.renewCertPeriodic.Start(true)
	case "online":
		interval := node.PullInterval * 60
		if interval <= 0 {
			interval = time.Hour
		}
		c.renewCertPeriodic = &task.Task{
			Name:     "syncOnlineCertTask",
			Interval: interval,
			Execute:  c.syncOnlineCertTask,
			Reload:   c.reloadTask,
		}
		log.WithField("tag", c.tag).Info("Start sync online cert")
		_ = c.renewCertPeriodic.Start(false)
	default:
		log.WithFields(log.Fields{
			"tag":      c.tag,
			"certmode": c.info.Common.CertInfo.CertMode,
		}).Warn("Skip unknown cert task mode")
	}
}

func (c *Controller) requestCert() error {
	cert := c.info.Common.CertInfo
	switch cert.CertMode {
	case "none", "":
	case "file":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
	case "dns", "http":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		l, err := NewLego(cert)
		if err != nil {
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCert()
		if err != nil {
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			cert.CertDomain,
			cert.CertFile,
			cert.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	case "online":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		certPEM, keyPEM, changed, err := c.fetchOnlineCertPair()
		if err != nil {
			if localErr := validateStoredCertPair(cert.CertFile, cert.KeyFile, cert.CertDomain); localErr == nil {
				log.WithFields(log.Fields{
					"tag": c.tag,
					"err": err,
				}).Warn("fetch online cert failed, keep local cert")
				return nil
			}
			return fmt.Errorf("fetch online cert error: %s", err)
		}
		if !changed {
			if err := validateStoredCertPair(cert.CertFile, cert.KeyFile, cert.CertDomain); err != nil {
				return fmt.Errorf("online cert not modified and local cert invalid: %s", err)
			}
			return nil
		}
		currentCert, currentKey, err := loadCertPair(cert.CertFile, cert.KeyFile)
		if err == nil && bytes.Equal(currentCert, certPEM) && bytes.Equal(currentKey, keyPEM) {
			return nil
		}
		if err := writeCertPair(cert.CertFile, cert.KeyFile, certPEM, keyPEM); err != nil {
			return fmt.Errorf("write online cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", cert.CertMode)
	}
	return nil
}

func (c *Controller) fetchOnlineCertPair() ([]byte, []byte, bool, error) {
	pair, changed, err := c.apiClient.GetNodeCertPair()
	if err != nil {
		return nil, nil, false, fmt.Errorf("get node cert pair error: %w", err)
	}
	if !changed {
		return nil, nil, false, nil
	}
	certPEM := []byte(pair.Cert)
	keyPEM := []byte(pair.Key)
	if err := validateOnlineCertPair(certPEM, keyPEM, c.info.Common.CertInfo.CertDomain); err != nil {
		return nil, nil, false, err
	}
	return certPEM, keyPEM, true, nil
}

func loadCertPair(certPath, keyPath string) ([]byte, []byte, error) {
	if !file.IsExist(certPath) || !file.IsExist(keyPath) {
		return nil, nil, fmt.Errorf("cert file path or key file path not exist")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file error: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file error: %w", err)
	}
	return certPEM, keyPEM, nil
}

func validateStoredCertPair(certPath, keyPath, domain string) error {
	certPEM, keyPEM, err := loadCertPair(certPath, keyPath)
	if err != nil {
		return err
	}
	return validateOnlineCertPair(certPEM, keyPEM, domain)
}

func validateOnlineCertPair(certPEM, keyPEM []byte, domain string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse cert pair error: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate error: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", leaf.NotBefore)
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate expired at %s", leaf.NotAfter)
	}
	if domain != "" {
		if err := leaf.VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate does not match domain %s: %w", domain, err)
		}
	}
	return nil
}

func writeCertPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := checkPath(certPath); err != nil {
		return fmt.Errorf("check cert path error: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert file error: %w", err)
	}
	if err := checkPath(keyPath); err != nil {
		return fmt.Errorf("check key path error: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0644); err != nil {
		return fmt.Errorf("write key file error: %w", err)
	}
	return nil
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	return nil
}
