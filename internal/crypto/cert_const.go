package crypto

import (
	"github.com/envoyproxy/gateway/internal/infrastructure/common"
	"path/filepath"
)

const (
	// CertBaseDir is the directory where all certificates are stored.
	CertBaseDir = "certs"

	CertEnvoy CertType = iota
	CertEnvoyGateway
	CertEnvoyRateLimit
	CertEnvoyOidcHmac

	CACertificateFilename = "ca.crt"
	CertificateFilename   = "tls.crt"
	PrivateKeyFilename    = "tls.key"

	HmacSecretFilename = "hmac-secret"
)

type CertType int

func (c CertType) DirPath(baseDir ...string) string {
	return filepath.Join(baseDir...)
}

func (c CertType) FilePath(filename string, baseDir ...string) string {
	return filepath.Join(append(baseDir, c.String(), filename)...)
}

func (c CertType) String() string {
	switch c {
	case CertEnvoy:
		return "envoy"
	case CertEnvoyGateway:
		return "envoy-gateway"
	case CertEnvoyRateLimit:
		return "envoy-rate-limit"
	case CertEnvoyOidcHmac:
		return "envoy-oidc-hmac"
	default:
		return ""
	}
}

func (c CertType) TLSCertFilePath(homeDir string) string {
	if c == CertEnvoyOidcHmac {
		return ""
	}
	return c.FilePath(CertificateFilename, homeDir, CertBaseDir)
}

func (c CertType) TLSKeyFilepath(homeDir string) string {
	if c == CertEnvoyOidcHmac {
		return ""
	}
	return c.FilePath(PrivateKeyFilename, homeDir, CertBaseDir)
}

func (c CertType) TLSCaFilePath(homeDir string) string {
	if c == CertEnvoyOidcHmac {
		return ""
	}
	return c.FilePath(CACertificateFilename, homeDir, CertBaseDir)
}

func (c CertType) HmacSecretPath(homeDir string) string {
	if c == CertEnvoyOidcHmac {
		return c.FilePath(HmacSecretFilename, homeDir, CertBaseDir)
	}
	return ""
}

func (c CertType) SdsCertFilename(homeDir string) string {
	if c == CertEnvoy {
		return c.FilePath(common.SdsCertFilename, homeDir, CertBaseDir)
	}
	return ""
}

func (c CertType) SdsCAFilename(homeDir string) string {
	if c == CertEnvoy {
		return c.FilePath(common.SdsCAFilename, homeDir, CertBaseDir)
	}
	return ""
}
