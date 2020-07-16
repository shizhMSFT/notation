package x509

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/docker/libtrust"
	"github.com/notaryproject/nv2/pkg/signature"
)

type verifier struct {
	roots *x509.CertPool
}

// NewVerifier creates a verifier
func NewVerifier(roots *x509.CertPool) (signature.Verifier, error) {
	if roots == nil {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		roots = pool
	}

	return &verifier{
		roots: roots,
	}, nil
}

func (v *verifier) Verify(content []byte, sig signature.Signature) error {
	if sig.Type != Type {
		return signature.ErrInvalidSignatureType
	}
	if len(sig.X5c) == 0 {
		return errors.New("empty x509 certificate chain")
	}

	certs := make([]*x509.Certificate, 0, len(sig.X5c))
	for _, certBytes := range sig.X5c {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	cert := certs[0]
	if _, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         v.roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return err
	}

	key, err := libtrust.FromCryptoPublicKey(crypto.PublicKey(cert.PublicKey))
	if err != nil {
		return err
	}

	return key.Verify(bytes.NewReader(content), sig.Algorithm, sig.Signature)
}
