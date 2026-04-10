//go:build linux

package crypto_time

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	tlsCertMaxItems       = 32
	tlsCertMaxReadBytes   = 256 * 1024
	tlsCertMaxCandidates  = 48
	tlsCertExpiryWarnDays = 30
)

// CollectLocalTlsCertInventory reads bounded PEM material from known paths; NotAfter and SHA-1 signature hints only.
func CollectLocalTlsCertInventory(ctx context.Context) *payload.LocalTlsCertInventory {
	paths := tlsCertCandidatePaths()
	if len(paths) == 0 {
		return nil
	}
	return collectLocalTlsCertInventoryFromPaths(paths)
}

func collectLocalTlsCertInventoryFromPaths(paths []string) *payload.LocalTlsCertInventory {
	now := time.Now()
	inv := &payload.LocalTlsCertInventory{}
	sha1Count := 0
	for _, p := range paths {
		if len(inv.Items) >= tlsCertMaxItems {
			break
		}
		if shouldSkipTLSInventoryPath(p) {
			continue
		}
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		inv.FilesScanned++
		data, err := readFileCapped(p, tlsCertMaxReadBytes)
		if err != nil {
			slog.Debug("tls cert inventory read failed", "path", p, "error", err)
			continue
		}
		cert := firstParseableCertFromPEM(data)
		if cert == nil {
			continue
		}
		usesSHA1 := certUsesSHA1(cert)
		if usesSHA1 {
			sha1Count++
		}
		expiresSoon := cert.NotAfter.After(now) && cert.NotAfter.Sub(now) <= tlsCertExpiryWarnDays*24*time.Hour
		inv.Items = append(inv.Items, payload.LocalTlsCertFileEntry{
			Path:                p,
			NotAfter:            cert.NotAfter.UTC().Format(time.RFC3339),
			ExpiresWithin30Days: boolPtrIfTrue(expiresSoon),
			UsesSha1Signature:   boolPtrIfTrue(usesSHA1),
		})
	}
	inv.Sha1SignatureCertCount = sha1Count
	if len(inv.Items) == 0 && inv.FilesScanned == 0 && inv.Error == "" {
		return nil
	}
	return inv
}

func boolPtrIfTrue(v bool) *bool {
	if !v {
		return nil
	}
	b := true
	return &b
}

func readFileCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func shouldSkipTLSInventoryPath(p string) bool {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		resolved = p
	}
	base := strings.ToLower(filepath.Base(resolved))
	if strings.Contains(base, "ca-bundle") || base == "ca-certificates.crt" {
		return true
	}
	return false
}

func tlsCertCandidatePaths() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if p == "" || len(out) >= tlsCertMaxCandidates {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	appendGlob := func(pattern string, max int) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return
		}
		sort.Strings(matches)
		for i := 0; i < len(matches) && i < max && len(out) < tlsCertMaxCandidates; i++ {
			add(matches[i])
		}
	}
	appendGlob("/etc/letsencrypt/live/*/fullchain.pem", 8)
	for _, single := range []string{
		"/etc/ssl/cert.pem",
		"/etc/pki/tls/cert.pem",
		"/etc/httpd/conf/ssl.crt/server.crt",
		"/etc/ssl/certs/ssl-cert-snakeoil.pem",
	} {
		if st, err := os.Stat(single); err == nil && !st.IsDir() {
			add(single)
		}
	}
	appendGlob("/etc/nginx/ssl/*.crt", 5)
	appendGlob("/etc/pki/tls/certs/*.pem", 20)
	appendGlob("/etc/pki/tls/certs/*.crt", 20)
	sort.Strings(out)
	return out
}

func firstParseableCertFromPEM(data []byte) *x509.Certificate {
	rest := data
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		rest = r
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		return cert
	}
	return nil
}

func certUsesSHA1(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}
