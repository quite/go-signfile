// SPDX-License-Identifier: GPL-3.0-or-later
package signfile

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	cms "github.com/quite/smimesign/ietf-cms"
	"github.com/quite/smimesign/ietf-cms/cmsoptions"
	"github.com/quite/smimesign/ietf-cms/oid"
)

// Based on the Linux kernel's scripts/sign-file.c -- the CMS variant
// (USE_PKCS7 not defined).
// - Currently only does attached signing
// - Not implemented: sign-file -k to use CMS_USE_KEYID

func init() {
	// Patches the oid package of ietf-cms so it produces more general
	// RSA OIDs, which is what the Linux kernel currently only accepts
	oid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[x509.RSA] = map[string]asn1.ObjectIdentifier{
		oid.DigestAlgorithmSHA1.String():   oid.PublicKeyAlgorithmRSA, // not SignatureAlgorithmSHA1WithRSA
		oid.DigestAlgorithmMD5.String():    oid.PublicKeyAlgorithmRSA, // not SignatureAlgorithmMD5WithRSA
		oid.DigestAlgorithmSHA256.String(): oid.PublicKeyAlgorithmRSA, // not SignatureAlgorithmSHA256WithRSA
		oid.DigestAlgorithmSHA384.String(): oid.PublicKeyAlgorithmRSA, // not SignatureAlgorithmSHA384WithRSA
		oid.DigestAlgorithmSHA512.String(): oid.PublicKeyAlgorithmRSA, // not SignatureAlgorithmSHA512WithRSA
	}
}

const (
	PKEY_ID_PKCS7 = 2
	magicNumber   = "~Module signature appended~\n"
)

// sigInfo returns the bytes corresponding to the struct
// module_signature. sigLen is the length of the actual signature in
// bytes (the struct's only variable field).
func sigInfo(sigLen uint32) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0)                                 // uint8_t  algo;       /* Public-key crypto algorithm [0]
	buf.WriteByte(0)                                 // uint8_t  hash;       /* Digest algorithm [0]
	buf.WriteByte(PKEY_ID_PKCS7)                     // uint8_t  id_type;    /* Key identifier type [PKEY_ID_PKCS7]
	buf.WriteByte(0)                                 // uint8_t  signer_len; /* Length of signer's name [0]
	buf.WriteByte(0)                                 // uint8_t  key_id_len; /* Length of key identifier [0]
	buf.Write([]byte{0, 0, 0})                       // uint8_t  __pad[3];
	_ = binary.Write(&buf, binary.BigEndian, sigLen) // uint32_t sig_len;    /* Length of signature data
	return buf.Bytes()
}

func SignKOAttached(key crypto.Signer, cert *x509.Certificate, ko []byte) ([]byte, error) {
	// TODO? This will use SHA256 for digest, which should be fine
	// since kernels almost always has CONFIG_CRYPTO_SHA256=y? The
	// exception is if key is ECDSA/P-384 or ECDSA/P-521 -- then
	// SHA384 or SHA512 is used respectively. See func
	// digestAlgorithmForPublicKey in ietf-cms.
	sd, err := cms.NewSignedData(ko)
	if err != nil {
		return nil, err
	}

	// passing our equivalent of CMS_NOATTR and CMS_NOCERTS
	if err = sd.Sign([]*x509.Certificate{cert}, key, cmsoptions.NoAttr(), cmsoptions.NoCerts()); err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	sd.Detached()

	signature, err := sd.ToDER()
	if err != nil {
		return nil, fmt.Errorf("failed encoding to DER: %w", err)
	}

	var signedKO bytes.Buffer
	signedKO.Write(ko)
	signedKO.Write(signature)
	signedKO.Write(sigInfo(uint32(len(signature))))
	signedKO.Write([]byte(magicNumber))

	return signedKO.Bytes(), nil
}
