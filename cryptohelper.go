package cryptohelper

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	mrand "math/rand"
	"strconv"
	"time"
)

const (
	AES128KeyLength = 16
	AES192KeyLength = 24
	AES256KeyLength = 32
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
// key for storage use the BytesToBase64 function.
func GenerateAES128Key() ([]byte, error) {
	return GenerateCryptoSequence(AES128KeyLength)
}

// GenerateAES192Key is an alias for GenerateCryptoSequence(24).
// An AES 192-bit key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the BytesToBase64 function.
func GenerateAES192Key() ([]byte, error) {
	return GenerateCryptoSequence(AES192KeyLength)
}

// GenerateAES256Key is an alias for GenerateCryptoSequence(32).
// An AES 256-bit key is expressed here as a byte slice. To obtain the plain text equivalent of this
// key for storage use the BytesToBase64 function.
func GenerateAES256Key() ([]byte, error) {
	return GenerateCryptoSequence(AES256KeyLength)
}

func EncryptTextAESGCM(key []byte, plaintext []byte) ([]byte, error) {

	// Create a new symmetric key cryptographic block cipher based on the key length
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Select the mode of operation we will use for this block cipher.
	// GCM (Galois/Counter Mode) is a good standard default to use.
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

	// Decrypt the ciphertext using the nonce and they key.
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// BytesToBase64 converts a byte array such as a key or ciphertext to a base64-encoded string for storage
// as an env var, text file, database field, etc.
func BytesToBase64(seq []byte) string {
	return base64.StdEncoding.EncodeToString(seq)
}

// Base64ToBytes converts a base64-encoded string such as a key or ciphertext read in from an env var, text
// file, or database field back into a byte array.
func Base64ToBytes(str string) ([]byte, error) {
	seq, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return seq, nil
}
