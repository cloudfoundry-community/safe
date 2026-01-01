package command

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/vault"
)

// X509IssueParams contains parameters for issuing a certificate
type X509IssueParams struct {
	OutputPath         string
	Subject            string
	CommonName         string
	Organization       string
	Country            string
	State              string
	Locality           string
	OrganizationalUnit string
	SANs               []string
	KeyBits            int
	TTL                string
	SignedBy           string
	IsCA               bool
	KeyUsages          []string
	SignatureAlgorithm string
}

// X509RevokeParams contains parameters for revoking a certificate
type X509RevokeParams struct {
	CertPath string
	CAPath   string
}

// X509RenewParams contains parameters for renewing a certificate
type X509RenewParams struct {
	CertPath           string
	NewSubject         string
	NewSANs            []string
	NewTTL             string
	NewKeyUsages       []string
	SignatureAlgorithm string
}

// X509ValidateParams contains parameters for validating a certificate
type X509ValidateParams struct {
	CertPath   string
	SignedBy   string
	CheckNames []string
	KeyBits    []int
	NotExpired bool
	NotRevoked bool
}

// X509ShowParams contains parameters for showing a certificate
type X509ShowParams struct {
	CertPath string
}

// Result messages

// X509IssuedMsg is sent when a certificate is successfully issued
type X509IssuedMsg struct {
	Path    string
	Subject string
	Expiry  time.Time
	IsCA    bool
}

// X509IssueErrorMsg is sent when certificate issuance fails
type X509IssueErrorMsg struct {
	Path string
	Err  error
}

// X509RevokedMsg is sent when a certificate is successfully revoked
type X509RevokedMsg struct {
	CertPath string
	CAPath   string
}

// X509RevokeErrorMsg is sent when certificate revocation fails
type X509RevokeErrorMsg struct {
	CertPath string
	Err      error
}

// X509RenewedMsg is sent when a certificate is successfully renewed
type X509RenewedMsg struct {
	Path   string
	Expiry time.Time
}

// X509RenewErrorMsg is sent when certificate renewal fails
type X509RenewErrorMsg struct {
	Path string
	Err  error
}

// X509ValidatedMsg is sent when a certificate is validated
type X509ValidatedMsg struct {
	Path    string
	Valid   bool
	Message string
	Checks  []X509ValidationCheck
}

// X509ValidationCheck represents a single validation check result
type X509ValidationCheck struct {
	Name   string
	Passed bool
	Detail string
}

// X509ValidateErrorMsg is sent when certificate validation fails
type X509ValidateErrorMsg struct {
	Path string
	Err  error
}

// X509CertDetailsMsg contains certificate details for display
type X509CertDetailsMsg struct {
	Path      string
	Subject   string
	Issuer    string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	KeySize   int
	SANs      []string
	KeyUsage  string
	IsCA      bool
	IsExpired bool
}

// X509ShowErrorMsg is sent when showing a certificate fails
type X509ShowErrorMsg struct {
	Path string
	Err  error
}

// IssueCertCmd creates a command to issue a new X.509 certificate
func IssueCertCmd(vaultAdapter *adapter.VaultAdapter, params X509IssueParams) tea.Cmd {
	return func() tea.Msg {
		// Build subject string
		subject := buildSubjectString(params)

		// Create the certificate
		cert, err := vault.NewCertificate(
			subject,
			params.SANs,
			params.KeyUsages,
			params.SignatureAlgorithm,
			params.KeyBits,
		)
		if err != nil {
			return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to create certificate: %w", err)}
		}

		// Make it a CA if requested
		if params.IsCA {
			cert.MakeCA()
		}

		// Get the signing CA
		var signingCA *vault.X509
		if params.SignedBy != "" {
			caSecret, err := vaultAdapter.Read(params.SignedBy)
			if err != nil {
				return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to read CA at %s: %w", params.SignedBy, err)}
			}
			signingCA, err = caSecret.X509(true)
			if err != nil {
				return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to parse CA: %w", err)}
			}
			if !signingCA.IsCA() {
				return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("certificate at %s is not a CA", params.SignedBy)}
			}
		} else {
			// Self-signed
			signingCA = cert
		}

		// Parse TTL
		ttl := parseTTL(params.TTL)

		// Sign the certificate
		err = signingCA.Sign(cert, ttl)
		if err != nil {
			return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to sign certificate: %w", err)}
		}

		// Save to vault
		err = cert.SaveTo(vaultAdapter.Vault(), params.OutputPath, false)
		if err != nil {
			return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to save certificate: %w", err)}
		}

		// If we used an external CA, save its updated state (serial number, CRL)
		if params.SignedBy != "" {
			err = signingCA.SaveTo(vaultAdapter.Vault(), params.SignedBy, false)
			if err != nil {
				return X509IssueErrorMsg{Path: params.OutputPath, Err: fmt.Errorf("failed to update CA serial: %w", err)}
			}
		}

		return X509IssuedMsg{
			Path:    params.OutputPath,
			Subject: subject,
			Expiry:  cert.Certificate.NotAfter,
			IsCA:    params.IsCA,
		}
	}
}

// RevokeCertCmd creates a command to revoke an X.509 certificate
func RevokeCertCmd(vaultAdapter *adapter.VaultAdapter, params X509RevokeParams) tea.Cmd {
	return func() tea.Msg {
		if params.CAPath == "" {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("CA path is required for revocation")}
		}

		// Read the CA
		caSecret, err := vaultAdapter.Read(params.CAPath)
		if err != nil {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("failed to read CA: %w", err)}
		}

		ca, err := caSecret.X509(true)
		if err != nil {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("failed to parse CA: %w", err)}
		}

		if !ca.IsCA() {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("certificate at %s is not a CA", params.CAPath)}
		}

		// Read the certificate to revoke
		certSecret, err := vaultAdapter.Read(params.CertPath)
		if err != nil {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := certSecret.X509(false)
		if err != nil {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("failed to parse certificate: %w", err)}
		}

		// Check if already revoked
		if ca.HasRevoked(cert) {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("certificate is already revoked")}
		}

		// Revoke the certificate
		ca.Revoke(cert)

		// Save the updated CA with new CRL
		err = ca.SaveTo(vaultAdapter.Vault(), params.CAPath, false)
		if err != nil {
			return X509RevokeErrorMsg{CertPath: params.CertPath, Err: fmt.Errorf("failed to save CA CRL: %w", err)}
		}

		return X509RevokedMsg{
			CertPath: params.CertPath,
			CAPath:   params.CAPath,
		}
	}
}

// RenewCertCmd creates a command to renew an X.509 certificate
func RenewCertCmd(vaultAdapter *adapter.VaultAdapter, params X509RenewParams) tea.Cmd {
	return func() tea.Msg {
		// Read the existing certificate
		certSecret, err := vaultAdapter.Read(params.CertPath)
		if err != nil {
			return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := certSecret.X509(true)
		if err != nil {
			return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse certificate: %w", err)}
		}

		// Calculate TTL
		var ttl time.Duration
		if params.NewTTL != "" {
			ttl = parseTTL(params.NewTTL)
		} else {
			// Use the same TTL as the original certificate
			ttl = cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
		}

		// Update subject if provided
		if params.NewSubject != "" {
			name, err := vault.ParseSubject(params.NewSubject)
			if err != nil {
				return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse subject: %w", err)}
			}
			cert.Certificate.Subject = name
		}

		// Update SANs if provided
		if len(params.NewSANs) > 0 {
			ips, domains, emails := vault.CategorizeSANs(params.NewSANs)
			cert.Certificate.IPAddresses = ips
			cert.Certificate.DNSNames = domains
			cert.Certificate.EmailAddresses = emails
		}

		// Update key usage if provided
		if len(params.NewKeyUsages) > 0 {
			ku, eku, err := vault.HandleJointKeyUsages(params.NewKeyUsages)
			if err != nil {
				return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse key usage: %w", err)}
			}
			cert.Certificate.KeyUsage = ku
			cert.Certificate.ExtKeyUsage = eku
		}

		// Update signature algorithm if provided
		if params.SignatureAlgorithm != "" {
			sigAlgo, err := vault.TranslateSignatureAlgorithm(params.SignatureAlgorithm)
			if err != nil {
				return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse signature algorithm: %w", err)}
			}
			cert.Certificate.SignatureAlgorithm = sigAlgo
		}

		// Re-sign the certificate
		// For CA certificates, they sign themselves
		// For non-CA certificates, we'd ideally use the original CA
		// but that would require knowing the CA path
		err = cert.Sign(cert, ttl)
		if err != nil {
			return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to sign certificate: %w", err)}
		}

		// Save the renewed certificate
		err = cert.SaveTo(vaultAdapter.Vault(), params.CertPath, false)
		if err != nil {
			return X509RenewErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to save certificate: %w", err)}
		}

		return X509RenewedMsg{
			Path:   params.CertPath,
			Expiry: cert.Certificate.NotAfter,
		}
	}
}

// ShowCertCmd creates a command to show certificate details
func ShowCertCmd(vaultAdapter *adapter.VaultAdapter, params X509ShowParams) tea.Cmd {
	return func() tea.Msg {
		// Read the certificate
		certSecret, err := vaultAdapter.Read(params.CertPath)
		if err != nil {
			return X509ShowErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := certSecret.X509(false)
		if err != nil {
			return X509ShowErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse certificate: %w", err)}
		}

		// Collect SANs
		var sans []string
		for _, dns := range cert.Certificate.DNSNames {
			sans = append(sans, dns)
		}
		for _, ip := range cert.Certificate.IPAddresses {
			sans = append(sans, ip.String())
		}
		for _, email := range cert.Certificate.EmailAddresses {
			sans = append(sans, email)
		}

		// Get key size
		keySize := 0
		if cert.PrivateKey != nil {
			keySize = cert.PrivateKey.N.BitLen()
		}

		// Format key usage
		keyUsage := formatKeyUsage(cert)

		return X509CertDetailsMsg{
			Path:      params.CertPath,
			Subject:   cert.Subject(),
			Issuer:    cert.Issuer(),
			Serial:    cert.FormatSerial(),
			NotBefore: cert.Certificate.NotBefore,
			NotAfter:  cert.Certificate.NotAfter,
			KeySize:   keySize,
			SANs:      sans,
			KeyUsage:  keyUsage,
			IsCA:      cert.IsCA(),
			IsExpired: cert.Expired(),
		}
	}
}

// ValidateCertCmd creates a command to validate an X.509 certificate
func ValidateCertCmd(vaultAdapter *adapter.VaultAdapter, params X509ValidateParams) tea.Cmd {
	return func() tea.Msg {
		var checks []X509ValidationCheck
		allPassed := true

		// Read the certificate
		certSecret, err := vaultAdapter.Read(params.CertPath)
		if err != nil {
			return X509ValidateErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := certSecret.X509(true)
		if err != nil {
			// Try without requiring key
			cert, err = certSecret.X509(false)
			if err != nil {
				return X509ValidateErrorMsg{Path: params.CertPath, Err: fmt.Errorf("failed to parse certificate: %w", err)}
			}
			checks = append(checks, X509ValidationCheck{
				Name:   "Private Key Present",
				Passed: false,
				Detail: "Certificate does not have a private key",
			})
			allPassed = false
		} else {
			// Validate key pair match
			err = cert.Validate()
			if err != nil {
				checks = append(checks, X509ValidationCheck{
					Name:   "Key Pair Match",
					Passed: false,
					Detail: err.Error(),
				})
				allPassed = false
			} else {
				checks = append(checks, X509ValidationCheck{
					Name:   "Key Pair Match",
					Passed: true,
					Detail: "Private key matches certificate public key",
				})
			}
		}

		// Check expiration
		if params.NotExpired || true { // Always check expiration by default
			if cert.Expired() {
				checks = append(checks, X509ValidationCheck{
					Name:   "Not Expired",
					Passed: false,
					Detail: fmt.Sprintf("Certificate expired on %s", cert.Certificate.NotAfter.Format(time.RFC3339)),
				})
				allPassed = false
			} else {
				daysRemaining := int(time.Until(cert.Certificate.NotAfter).Hours() / 24)
				checks = append(checks, X509ValidationCheck{
					Name:   "Not Expired",
					Passed: true,
					Detail: fmt.Sprintf("Certificate valid until %s (%d days remaining)", cert.Certificate.NotAfter.Format(time.RFC3339), daysRemaining),
				})
			}
		}

		// Check key bits
		if len(params.KeyBits) > 0 && cert.PrivateKey != nil {
			err = cert.CheckStrength(params.KeyBits...)
			if err != nil {
				checks = append(checks, X509ValidationCheck{
					Name:   "Key Strength",
					Passed: false,
					Detail: err.Error(),
				})
				allPassed = false
			} else {
				checks = append(checks, X509ValidationCheck{
					Name:   "Key Strength",
					Passed: true,
					Detail: fmt.Sprintf("Key strength is %d bits", cert.PrivateKey.N.BitLen()),
				})
			}
		}

		// Check name validity
		if len(params.CheckNames) > 0 {
			valid, err := cert.ValidFor(params.CheckNames...)
			if !valid {
				checks = append(checks, X509ValidationCheck{
					Name:   "Name Validity",
					Passed: false,
					Detail: err.Error(),
				})
				allPassed = false
			} else {
				checks = append(checks, X509ValidationCheck{
					Name:   "Name Validity",
					Passed: true,
					Detail: fmt.Sprintf("Certificate is valid for specified names"),
				})
			}
		}

		// Check if signed by specified CA
		if params.SignedBy != "" {
			caSecret, err := vaultAdapter.Read(params.SignedBy)
			if err != nil {
				checks = append(checks, X509ValidationCheck{
					Name:   "Signed By CA",
					Passed: false,
					Detail: fmt.Sprintf("Failed to read CA: %s", err.Error()),
				})
				allPassed = false
			} else {
				ca, err := caSecret.X509(false)
				if err != nil {
					checks = append(checks, X509ValidationCheck{
						Name:   "Signed By CA",
						Passed: false,
						Detail: fmt.Sprintf("Failed to parse CA: %s", err.Error()),
					})
					allPassed = false
				} else {
					// Verify signature
					err = cert.Certificate.CheckSignatureFrom(ca.Certificate)
					if err != nil {
						checks = append(checks, X509ValidationCheck{
							Name:   "Signed By CA",
							Passed: false,
							Detail: fmt.Sprintf("Certificate was not signed by %s: %s", params.SignedBy, err.Error()),
						})
						allPassed = false
					} else {
						checks = append(checks, X509ValidationCheck{
							Name:   "Signed By CA",
							Passed: true,
							Detail: fmt.Sprintf("Certificate was signed by %s", params.SignedBy),
						})
					}

					// Check revocation if requested
					if params.NotRevoked {
						if ca.HasRevoked(cert) {
							checks = append(checks, X509ValidationCheck{
								Name:   "Not Revoked",
								Passed: false,
								Detail: "Certificate has been revoked by the CA",
							})
							allPassed = false
						} else {
							checks = append(checks, X509ValidationCheck{
								Name:   "Not Revoked",
								Passed: true,
								Detail: "Certificate is not on the CA's revocation list",
							})
						}
					}
				}
			}
		}

		message := "All validation checks passed"
		if !allPassed {
			message = "One or more validation checks failed"
		}

		return X509ValidatedMsg{
			Path:    params.CertPath,
			Valid:   allPassed,
			Message: message,
			Checks:  checks,
		}
	}
}

// CopyPEMCmd creates a command to copy certificate PEM to clipboard
func CopyPEMCmd(vaultAdapter *adapter.VaultAdapter, path string, includeKey bool) tea.Cmd {
	return func() tea.Msg {
		secret, err := vaultAdapter.Read(path)
		if err != nil {
			return X509CopyErrorMsg{Path: path, Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		var content string
		if includeKey && secret.Has("combined") {
			content = secret.Get("combined")
		} else if secret.Has("certificate") {
			content = secret.Get("certificate")
		} else {
			return X509CopyErrorMsg{Path: path, Err: fmt.Errorf("no certificate found at path")}
		}

		return X509PEMCopiedMsg{
			Path:    path,
			Content: content,
		}
	}
}

// X509CopyErrorMsg is sent when copying PEM fails
type X509CopyErrorMsg struct {
	Path string
	Err  error
}

// X509PEMCopiedMsg is sent when PEM is copied
type X509PEMCopiedMsg struct {
	Path    string
	Content string
}

// Helper functions

// buildSubjectString builds a subject string from params
func buildSubjectString(params X509IssueParams) string {
	if params.Subject != "" {
		return params.Subject
	}

	var parts []string

	if params.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", params.CommonName))
	} else if len(params.SANs) > 0 {
		parts = append(parts, fmt.Sprintf("CN=%s", params.SANs[0]))
	}

	if params.Organization != "" {
		parts = append(parts, fmt.Sprintf("O=%s", params.Organization))
	}

	if params.OrganizationalUnit != "" {
		parts = append(parts, fmt.Sprintf("OU=%s", params.OrganizationalUnit))
	}

	if params.Locality != "" {
		parts = append(parts, fmt.Sprintf("L=%s", params.Locality))
	}

	if params.State != "" {
		parts = append(parts, fmt.Sprintf("ST=%s", params.State))
	}

	if params.Country != "" {
		parts = append(parts, fmt.Sprintf("C=%s", params.Country))
	}

	if len(parts) == 0 {
		return "CN=certificate"
	}

	return "/" + joinSubjectParts(parts)
}

func joinSubjectParts(parts []string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "/"
		}
		result += part
	}
	return result
}

// parseTTL parses a TTL string like "365d" or "1y" into a duration
func parseTTL(ttl string) time.Duration {
	if ttl == "" {
		return 365 * 24 * time.Hour
	}

	var value int
	var unit string
	n, err := fmt.Sscanf(ttl, "%d%s", &value, &unit)
	if err != nil || n < 1 || value <= 0 {
		return 365 * 24 * time.Hour
	}

	switch unit {
	case "d", "day", "days", "":
		return time.Duration(value) * 24 * time.Hour
	case "w", "week", "weeks":
		return time.Duration(value) * 7 * 24 * time.Hour
	case "m", "month", "months":
		return time.Duration(value) * 30 * 24 * time.Hour
	case "y", "year", "years":
		return time.Duration(value) * 365 * 24 * time.Hour
	case "h", "hour", "hours":
		return time.Duration(value) * time.Hour
	default:
		// If no unit, assume days
		return time.Duration(value) * 24 * time.Hour
	}
}

// formatKeyUsage formats key usage flags to a readable string
func formatKeyUsage(cert *vault.X509) string {
	var usages []string

	c := cert.Certificate

	// Standard key usage
	if c.KeyUsage&1 != 0 {
		usages = append(usages, "Digital Signature")
	}
	if c.KeyUsage&2 != 0 {
		usages = append(usages, "Non Repudiation")
	}
	if c.KeyUsage&4 != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if c.KeyUsage&8 != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if c.KeyUsage&16 != 0 {
		usages = append(usages, "Key Agreement")
	}
	if c.KeyUsage&32 != 0 {
		usages = append(usages, "Cert Sign")
	}
	if c.KeyUsage&64 != 0 {
		usages = append(usages, "CRL Sign")
	}

	// Extended key usage
	for _, eku := range c.ExtKeyUsage {
		switch eku {
		case 1:
			usages = append(usages, "Server Auth")
		case 2:
			usages = append(usages, "Client Auth")
		case 3:
			usages = append(usages, "Code Signing")
		case 4:
			usages = append(usages, "Email Protection")
		case 8:
			usages = append(usages, "Time Stamping")
		}
	}

	if len(usages) == 0 {
		return "None"
	}

	result := ""
	for i, u := range usages {
		if i > 0 {
			result += ", "
		}
		result += u
	}
	return result
}

// CreateCACmd is a convenience function to create a self-signed CA certificate
func CreateCACmd(vaultAdapter *adapter.VaultAdapter, path, commonName string, keyBits int, ttlDays int) tea.Cmd {
	return IssueCertCmd(vaultAdapter, X509IssueParams{
		OutputPath:         path,
		CommonName:         commonName,
		SANs:               []string{commonName},
		KeyBits:            keyBits,
		TTL:                fmt.Sprintf("%dd", ttlDays),
		IsCA:               true,
		KeyUsages:          []string{"key_cert_sign", "crl_sign", "digital_signature"},
		SignatureAlgorithm: "sha512",
	})
}

// CreateServerCertCmd is a convenience function to create a server certificate
func CreateServerCertCmd(vaultAdapter *adapter.VaultAdapter, path, caPath, commonName string, sans []string, keyBits int, ttlDays int) tea.Cmd {
	return IssueCertCmd(vaultAdapter, X509IssueParams{
		OutputPath:         path,
		CommonName:         commonName,
		SANs:               sans,
		KeyBits:            keyBits,
		TTL:                fmt.Sprintf("%dd", ttlDays),
		SignedBy:           caPath,
		IsCA:               false,
		KeyUsages:          []string{"digital_signature", "key_encipherment", "server_auth"},
		SignatureAlgorithm: "sha512",
	})
}

// CreateClientCertCmd is a convenience function to create a client certificate
func CreateClientCertCmd(vaultAdapter *adapter.VaultAdapter, path, caPath, commonName string, keyBits int, ttlDays int) tea.Cmd {
	return IssueCertCmd(vaultAdapter, X509IssueParams{
		OutputPath:         path,
		CommonName:         commonName,
		SANs:               []string{commonName},
		KeyBits:            keyBits,
		TTL:                fmt.Sprintf("%dd", ttlDays),
		SignedBy:           caPath,
		IsCA:               false,
		KeyUsages:          []string{"digital_signature", "client_auth"},
		SignatureAlgorithm: "sha512",
	})
}

// GetCertFormValues converts CertFormValues to X509IssueParams
func GetCertFormValues(values component.CertFormValues) X509IssueParams {
	return X509IssueParams{
		OutputPath:         values.OutputPath,
		CommonName:         values.CommonName,
		Organization:       values.Organization,
		Country:            values.Country,
		State:              values.State,
		SANs:               values.SANs,
		KeyBits:            values.KeyBits,
		TTL:                values.TTL,
		SignedBy:           values.SignedBy,
		IsCA:               values.IsCA,
		KeyUsages:          values.KeyUsageList(),
		SignatureAlgorithm: values.SignatureAlgorithm,
	}
}
