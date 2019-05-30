package cryptohelper_test

import (
	"bytes"
	"testing"

	"github.com/gregtzar/cryptohelper"
)

func TestGeneratePIN(t *testing.T) {

	type tcase struct {
		expectedLen int
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			pinA := cryptohelper.GeneratePIN(tc.expectedLen)
			pinB := cryptohelper.GeneratePIN(tc.expectedLen)

			if len(pinA) != tc.expectedLen {
				t.Errorf("expected len(%v) but got (%v)", tc.expectedLen, len(pinA))
				return
			}

			if len(pinB) != tc.expectedLen {
				t.Errorf("expected len(%v) but got (%v)", tc.expectedLen, len(pinB))
				return
			}

			if pinA == pinB {
				t.Error("expected not equals")
				return
			}
		}
	}

	tests := map[string]tcase{
		"4 character random pin": {
			expectedLen: 4,
		},
		"20 character random pin": {
			expectedLen: 20,
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}
}

func TestGenerateCryptoSequence(t *testing.T) {

	type tcase struct {
		expectedLen int
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			var seqA []byte
			var seqB []byte
			var errA error
			var errB error

			seqA, errA = cryptohelper.GenerateCryptoSequence(tc.expectedLen)
			seqB, errB = cryptohelper.GenerateCryptoSequence(tc.expectedLen)

			compareRandomBytes(t, tc.expectedLen, seqA, seqB, errA, errB)
		}
	}

	tests := map[string]tcase{
		"10 byte random sequence": {
			expectedLen: 10,
		},
		"50 byte random sequence": {
			expectedLen: 50,
		},
		"200 byte random sequence": {
			expectedLen: 200,
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}

func TestGenerateAESKeys(t *testing.T) {

	type tcase struct {
		expectedLen int
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			var seqA []byte
			var seqB []byte
			var errA error
			var errB error

			switch tc.expectedLen {
			case cryptohelper.AES128KeyLength:
				seqA, errA = cryptohelper.GenerateAES128Key()
				seqB, errB = cryptohelper.GenerateAES128Key()
			case cryptohelper.AES192KeyLength:
				seqA, errA = cryptohelper.GenerateAES192Key()
				seqB, errB = cryptohelper.GenerateAES192Key()
			case cryptohelper.AES256KeyLength:
				seqA, errA = cryptohelper.GenerateAES256Key()
				seqB, errB = cryptohelper.GenerateAES256Key()
			default:
				t.Errorf("expected valid len but got (%v)", tc.expectedLen)
			}

			compareRandomBytes(t, tc.expectedLen, seqA, seqB, errA, errB)
		}
	}

	tests := map[string]tcase{
		"AES128 Key": {
			expectedLen: cryptohelper.AES128KeyLength,
		},
		"AES192 Key": {
			expectedLen: cryptohelper.AES192KeyLength,
		},
		"AES256 Key": {
			expectedLen: cryptohelper.AES256KeyLength,
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}

func TestGenerateHMACKeys(t *testing.T) {

	type tcase struct {
		expectedLen int
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			var seqA []byte
			var seqB []byte
			var errA error
			var errB error

			switch tc.expectedLen {
			case cryptohelper.HMACSHA256KeyLength:
				seqA, errA = cryptohelper.GenerateHMACSHA256Key()
				seqB, errB = cryptohelper.GenerateHMACSHA256Key()
			case cryptohelper.HMACSHA512KeyLength:
				seqA, errA = cryptohelper.GenerateHMACSHA512Key()
				seqB, errB = cryptohelper.GenerateHMACSHA512Key()
			default:
				t.Errorf("expected valid len but got (%v)", tc.expectedLen)
			}

			compareRandomBytes(t, tc.expectedLen, seqA, seqB, errA, errB)
		}
	}

	tests := map[string]tcase{
		"HMAC SHA-256 Key": {
			expectedLen: cryptohelper.HMACSHA256KeyLength,
		},
		"HMAC SHA-512 Key": {
			expectedLen: cryptohelper.HMACSHA512KeyLength,
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}

func compareRandomBytes(t *testing.T, expectedLen int, seqA []byte, seqB []byte, errA error, errB error) {
	if errA != nil {
		t.Errorf("expected nil err but got (%v)", errA)
		return
	}

	if errB != nil {
		t.Errorf("expected nil err but got (%v)", errB)
		return
	}

	if len(seqA) != expectedLen {
		t.Errorf("expected len (%v) but got (%v)", expectedLen, len(seqA))
		return
	}

	if len(seqB) != expectedLen {
		t.Errorf("expected len (%v) but got (%v)", expectedLen, len(seqB))
		return
	}

	if bytes.Equal(seqA, seqB) {
		t.Error("expected not equals")
		return
	}
}

func TestAESGSMEncryptDecrypt(t *testing.T) {

	type tcase struct {
		keyLen  int
		message string
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			var key []byte
			var err error

			switch tc.keyLen {
			case cryptohelper.AES128KeyLength:
				key, err = cryptohelper.GenerateAES128Key()
			case cryptohelper.AES192KeyLength:
				key, err = cryptohelper.GenerateAES192Key()
			case cryptohelper.AES256KeyLength:
				key, err = cryptohelper.GenerateAES256Key()
			default:
				t.Errorf("expected valid key len but got (%v)", tc.keyLen)
			}

			if err != nil {
				t.Errorf("expected nil key err but got (%v)", err)
				return
			}

			ciphertext, err := cryptohelper.EncryptTextAESGCM(key, []byte(tc.message))
			if err != nil {
				t.Errorf("expected nil encrypt err but got (%v)", err)
				return
			}

			plaintext, err := cryptohelper.DecryptTextAESGCM(key, ciphertext)
			if err != nil {
				t.Errorf("expected nil decrypt err but got (%v)", err)
				return
			}

			if string(plaintext) != tc.message {
				t.Error("expected decrypted plaintext to match original message")
				return
			}
		}
	}

	tests := map[string]tcase{
		"AES128": {
			keyLen:  cryptohelper.AES128KeyLength,
			message: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
		"AES192": {
			keyLen:  cryptohelper.AES192KeyLength,
			message: "Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas.",
		},
		"AES256": {
			keyLen:  cryptohelper.AES256KeyLength,
			message: "Vivamus lacinia ex nec nibh malesuada, sit amet hendrerit leo accumsan.",
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}

func TestHMACHash(t *testing.T) {

	type tcase struct {
		keyLen  int
		message string
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			var key []byte
			var err error
			var hashA []byte
			var hashB []byte

			switch tc.keyLen {
			case cryptohelper.HMACSHA256KeyLength:
				key, err = cryptohelper.GenerateHMACSHA256Key()
				if err != nil {
					t.Errorf("expected nil key err but got (%v)", err)
					return
				}
				hashA = cryptohelper.CreateHMACSHA256(key, []byte(tc.message))
				hashB = cryptohelper.CreateHMACSHA256(key, []byte(tc.message))
			case cryptohelper.HMACSHA512KeyLength:
				key, err = cryptohelper.GenerateHMACSHA512Key()
				if err != nil {
					t.Errorf("expected nil key err but got (%v)", err)
					return
				}
				hashA = cryptohelper.CreateHMACSHA512(key, []byte(tc.message))
				hashB = cryptohelper.CreateHMACSHA512(key, []byte(tc.message))
			default:
				t.Errorf("expected valid key len but got (%v)", tc.keyLen)
			}

			if !cryptohelper.CompareHMAC(hashA, hashB) {
				t.Error("expected hash equality")
				return
			}
		}
	}

	tests := map[string]tcase{
		"HMAC SHA-256": {
			keyLen:  cryptohelper.HMACSHA256KeyLength,
			message: "Vivamus lacinia ex nec nibh malesuada, sit amet hendrerit leo accumsan.",
		},
		"HMAC SHA-512": {
			keyLen:  cryptohelper.HMACSHA512KeyLength,
			message: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}

const (
	encHex = "hexadecimal"
	encB64 = "base64"
)

func TestEncodeDecode(t *testing.T) {

	type tcase struct {
		encType            string
		rawMessageLen      int
		expectedEncodedLen int
	}

	fn := func(tc tcase) func(t *testing.T) {
		return func(t *testing.T) {

			original, err := cryptohelper.GenerateCryptoSequence(tc.rawMessageLen)
			if err != nil {
				t.Errorf("expected nil sequence err but got (%v)", err)
				return
			}

			var encoded string
			var decoded []byte
			var decodeErr error

			switch tc.encType {
			case encHex:
				encoded = cryptohelper.EncodeHex(original)
				decoded, decodeErr = cryptohelper.DecodeHex(encoded)
			case encB64:
				encoded = cryptohelper.EncodeB64(original)
				decoded, decodeErr = cryptohelper.DecodeB64(encoded)
			default:
				t.Errorf("expected valid enc type but got (%v)", tc.encType)
			}

			if decodeErr != nil {
				t.Errorf("expected nil decode err but got (%v)", err)
				return
			}

			if len(encoded) != tc.expectedEncodedLen {
				t.Errorf("expected encoded len (%v) but got (%v)", tc.expectedEncodedLen, len(encoded))
				return
			}

			if !bytes.Equal(original, decoded) {
				t.Error("expected equals")
				return
			}
		}
	}

	tests := map[string]tcase{
		"Hex String Encoding": {
			encType:            encHex,
			rawMessageLen:      32,
			expectedEncodedLen: 64,
		},
		"Base64 String Encoding": {
			encType:            encB64,
			rawMessageLen:      32,
			expectedEncodedLen: 44,
		},
	}

	for name, tc := range tests {
		t.Run(name, fn(tc))
	}

}
