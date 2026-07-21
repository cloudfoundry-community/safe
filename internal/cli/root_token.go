package cli

// resolveRootToken picks the root token for a local Vault. A fresh
// initialization already yields a root token; only a pre-existing vault
// (unsealed with a supplied key) needs one generated via sys/generate-root.
// OpenBao removed that API, so generation is a last resort rather than the
// default path.
func resolveRootToken(initToken string, generate func() (string, error)) (string, error) {
	if initToken != "" {
		return initToken, nil
	}
	return generate()
}
