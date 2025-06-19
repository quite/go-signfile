// SPDX-License-Identifier: GPL-3.0-or-later
package signfile

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"

	"github.com/foxboron/go-uefi/pkcs7"
)

// Based on the Linux kernel's scripts/sign-file.c -- the CMS variant
// (USE_PKCS7 not defined).
// - Currently only does attached signing
// - Not implemented: sign-file -k to use CMS_USE_KEYID

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
	signature, err := pkcs7.SignPKCS7(key, cert, pkcs7.OIDData, ko, pkcs7.NoAttr(), pkcs7.NoCerts())
	if err != nil {
		return nil, err
	}

	var signedKO bytes.Buffer
	signedKO.Write(ko)
	signedKO.Write(signature)
	signedKO.Write(sigInfo(uint32(len(signature))))
	signedKO.Write([]byte(magicNumber))

	return signedKO.Bytes(), nil
}
