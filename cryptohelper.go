package cryptohelper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	mrand "math/rand"
	"strconv"
	"time"
)

const (
	AES128KeyLength     = 16
	AES192KeyLength     = 24
	AES256KeyLength     = 32
	HMACSHA256KeyLength = 32
	HMACSHA512KeyLength = 64
)

var (
	ErrCipherTextMissingNonce = errors.New("The nonce cannot be parsed from the cipher text because the length of the cipher text is too short")
)

// GeneratePIN creates a psuedo-random pin number style security code of the designated character length.
// The output of this function is suitable for generating pin numbers for use in a two-factor auth system
// which uses security code verification over a medium like SMS or email.
func GeneratePIN(length int) string {
	mrand.Seed(time.Now().UnixNano())
	pin := ""
	for len(pin) < length {
		pin += strconv.Itoa(mrand.Intn(9))
	}
	return pin
}

// GenerateCryptoSequence returns a cryptographically secure psuedo-random sequence of bytes of the
// indicated length. The output of this function is suitable for generating a secret key for use in a
// symmetrical encryption algorithm such as AES, a random nonce, etc. This method relies on specifics
// of the underlying operating system and if a byte slice of the full indicated length cannot be generated
// an error will be returned.
func GenerateCryptoSequence(length int) ([]byte, error) {
	seq := make([]byte, length)
	_, err := crand.Read(seq)
	if err != nil {
		return nil, err
	}
	return seq, nil
}

// GenerateAES128Key is an alias for GenerateCryptoSequence(16).
// An AES 128-bit key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the EncodeB64 or EncodeHex function.
func GenerateAES128Key() ([]byte, error) {
	return GenerateCryptoSequence(AES128KeyLength)
}

// GenerateAES192Key is an alias for GenerateCryptoSequence(24).
// An AES 192-bit key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the EncodeB64 or EncodeHex function.
func GenerateAES192Key() ([]byte, error) {
	return GenerateCryptoSequence(AES192KeyLength)
}

// GenerateAES256Key is an alias for GenerateCryptoSequence(32).
// An AES 256-bit key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the EncodeB64 or EncodeHex function.
func GenerateAES256Key() ([]byte, error) {
	return GenerateCryptoSequence(AES256KeyLength)
}

// GenerateHMACSHA256Key is an alias for GenerateCryptoSequence(32).
// An HMAC SHA-256 key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the EncodeB64 or EncodeHex function.
func GenerateHMACSHA256Key() ([]byte, error) {
	return GenerateCryptoSequence(HMACSHA256KeyLength)
}

// GenerateHMACSHA512Key is an alias for GenerateCryptoSequence(64).
// An HMAC SHA-512 key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the EncodeB64 or EncodeHex function.
func GenerateHMACSHA512Key() ([]byte, error) {
	return GenerateCryptoSequence(HMACSHA512KeyLength)
}

// EncryptTextAESGCM encrypts a chunk of plaintext using AES 128/192/256 symmetrical encryption with the
// strength based on the key length. 128-bit requires a key length of 16, 192-bit requires a key length of 24,
// and 256-bit requires a key length of 32. An error will be returned if the key is not of an acceptable
// length. The mode of operation used for the block cipher is GCM (Galois/Counter Mode). A 12-byte random
// nonce will be prepended to the final ciphertext and must be parsed back out and used during the decryption
// process. If the DecryptTextAESGCM function is used to decrypt the ciphertext then the nonce will be
// handled transparently.
func EncryptTextAESGCM(key []byte, plaintext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a random nonce of the standard length required by the gcm.
	nonce, err := GenerateCryptoSequence(aesgcm.NonceSize())
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext using the nonce and the key. Note that we pass the
	// nonce in as the first argument, which ensures that it will be prepended to
	// the encrypted text and stored along with it. When it comes time to decrypt
	// this text we will need to parse the nonse back out and use it again.
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil

}

// DecryptTextAESGCM decrypts a chunk of ciphertext which was encrypted using AES 128/192/256
// symmetrical encryption with the mode of operation used for the block cipher being GCM. This
// function requires the same key used to encrypt the plaintext and also expects the 12-byte random
// nonce used to encrypt the plaintext to be prepended to the ciphertext. If the EncryptTextAESGCM
// function was used to generate the ciphertext then the nonce will be handled transparently.
func DecryptTextAESGCM(key []byte, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Obtain the standard nonce length from the gcm and validate the ciphertext
	noncesize := aesgcm.NonceSize()
	if len(ciphertext) < noncesize {
		return nil, ErrCipherTextMissingNonce
	}

	// Parse the nonse from the ciphertext
	nonce, ciphertext := ciphertext[:noncesize], ciphertext[noncesize:]

	// Decrypt the ciphertext using the nonce and the key.
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// CreateHMACSHA256 creates a cryptographic hash of a plaintext message using the Keyed-Hash Message
// Authentication Code (HMAC) method and the SHA-256 hashing algorithm. While the key can be any length
// it should be 32 random bytes for optimal security. The output can be converted to a string for storage using
// EncodeHex or EncodeB64. For a secure way to compare the output with another hmac hash use CompareHMAC.
func CreateHMACSHA256(key []byte, plaintext []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(plaintext)
	return hash.Sum(nil)
}

// CreateHMACSHA512 creates a cryptographic hash of a plaintext message using the Keyed-Hash Message
// Authentication Code (HMAC) method and the SHA-512 hashing algorithm. While the key can be any length
// it should be 64 random bytes for optimal security. The output can be converted to a string for storage using
// EncodeHex or EncodeB64. For a secure way to compare the output with another hmac hash use CompareHMAC.
func CreateHMACSHA512(key []byte, plaintext []byte) []byte {
	hash := hmac.New(sha512.New, key)
	hash.Write(plaintext)
	return hash.Sum(nil)
}

// CompareHMAC is a secure way to compare two HMAC hash outputs for equality without leaking timing
// side-channel information.
func CompareHMAC(hashA []byte, hashB []byte) bool {
	return hmac.Equal(hashA, hashB)
}

// EncodeHex converts a byte slice such as a key, hash, or ciphertext to a hexadecimal string for storage.
func EncodeHex(seq []byte) string {
	return hex.EncodeToString(seq)
}

// DecodeHex converts a hexadecimal string such as a stored key, hash, or ciphertext back into a byte slice.
func DecodeHex(str string) ([]byte, error) {
	seq, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return seq, nil
}

// EncodeB64 converts a byte slice such as a key, hash, or ciphertext to a base64-encoded string for storage.
func EncodeB64(seq []byte) string {
	return base64.StdEncoding.EncodeToString(seq)
}

// DecodeB64 converts a base64-encoded string such as a stored key, hash, or ciphertext back into a byte slice.
func DecodeB64(str string) ([]byte, error) {
	seq, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return seq, nil
}
