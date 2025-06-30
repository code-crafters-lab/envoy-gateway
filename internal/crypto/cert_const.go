package crypto

const (
	// CertBaseDir is the directory where all certificates are stored.
	CertBaseDir = "certs"

	CertEnvoyDir          = "envoy"
	CertEnvoyGatewayDir   = "envoy-gateway"
	CertEnvoyRateLimitDir = "envoy-rate-limit"
	CertEnvoyOidcHmacDir  = "envoy-oidc-hmac"

	CACertificateFile = "ca.crt"
	CertificateFile   = "tls.crt"
	PrivateKeyFile    = "tls.key"
	HmacSecretFile    = "hmac-secret"
)
