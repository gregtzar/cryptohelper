package main

import (
	"github.com/gregtzar/go-cryptohelper"
	"log"
)

func main() {
	pinA := cryptohelper.GeneratePIN(6)
	pinB := cryptohelper.GeneratePIN(6)
	pinC := cryptohelper.GeneratePIN(6)

	log.Printf("pinA: %v", pinA)
	log.Printf("pinB: %v", pinB)
	log.Printf("pinC: %v", pinC)

	key128A, err := cryptohelper.GenerateAES128Key()
	if err != nil {
		log.Fatal(err)
	}
	key128B, err := cryptohelper.GenerateAES128Key()
	if err != nil {
		log.Fatal(err)
	}
	key128C, err := cryptohelper.GenerateAES128Key()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key128A b64: %v", cryptohelper.BytesToBase64(key128A))
	log.Printf("key128B b64: %v", cryptohelper.BytesToBase64(key128B))
	log.Printf("key128C b64: %v", cryptohelper.BytesToBase64(key128C))
	log.Printf("len: %v", len(cryptohelper.BytesToBase64(key128C)))

	key192A, err := cryptohelper.GenerateAES192Key()
	if err != nil {
		log.Fatal(err)
	}
	key192B, err := cryptohelper.GenerateAES192Key()
	if err != nil {
		log.Fatal(err)
	}
	key192C, err := cryptohelper.GenerateAES192Key()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key192A b64: %v", cryptohelper.BytesToBase64(key192A))
	log.Printf("key192B b64: %v", cryptohelper.BytesToBase64(key192B))
	log.Printf("key192C b64: %v", cryptohelper.BytesToBase64(key192C))
	log.Printf("len: %v", len(cryptohelper.BytesToBase64(key192C)))

	key256A, err := cryptohelper.GenerateAES256Key()
	if err != nil {
		log.Fatal(err)
	}
	key256B, err := cryptohelper.GenerateAES256Key()
	if err != nil {
		log.Fatal(err)
	}
	key256C, err := cryptohelper.GenerateAES256Key()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("key256A b64: %v", cryptohelper.BytesToBase64(key256A))
	log.Printf("key256B b64: %v", cryptohelper.BytesToBase64(key256B))
	log.Printf("key256C b64: %v", cryptohelper.BytesToBase64(key256C))
	log.Printf("key256A hex: %v", cryptohelper.BytesToHex(key256A))
	log.Printf("key256B hex: %v", cryptohelper.BytesToHex(key256B))
	log.Printf("key256C hex: %v", cryptohelper.BytesToHex(key256C))
	log.Printf("len: %v", len(cryptohelper.BytesToBase64(key256C)))

	plaintext := "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit."
	log.Printf("plaintext: %v", plaintext)

	cipherbytes, err := cryptohelper.EncryptTextAESGCM(key256A, []byte(plaintext))
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := cryptohelper.BytesToBase64(cipherbytes)
	log.Printf("ciphertext b64: %v", ciphertext)
	log.Printf("ciphertext hex: %v", cryptohelper.BytesToHex(cipherbytes))

	recipherbytes, err := cryptohelper.Base64ToBytes(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	decipherbytes, err := cryptohelper.DecryptTextAESGCM(key256A, recipherbytes)
	if err != nil {
		log.Fatal(err)
	}

	deciphertext := string(decipherbytes)
	log.Printf("deciphertext: %v", deciphertext)

	hmac256Key, err := cryptohelper.GenerateHMACSHA256Key()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("hmac256Key hex: %v (%v)", cryptohelper.BytesToHex(hmac256Key), len(cryptohelper.BytesToHex(hmac256Key)))
	log.Printf("hmac256Key b64: %v (%v)", cryptohelper.BytesToBase64(hmac256Key), len(cryptohelper.BytesToBase64(hmac256Key)))

	hmac512Key, err := cryptohelper.GenerateHMACSHA512Key()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("hmac512Key hex: %v (%v)", cryptohelper.BytesToHex(hmac512Key), len(cryptohelper.BytesToHex(hmac512Key)))
	log.Printf("hmac512Key b64: %v (%v)", cryptohelper.BytesToBase64(hmac512Key), len(cryptohelper.BytesToBase64(hmac512Key)))

	hmacMsg := []byte("Neque porro quisquam est qui dolorem ipsum quia dolor sit amet.")

	hmac256hashA := cryptohelper.CreateHMACSHA256(hmac256Key, hmacMsg)
	hmac256hashB := cryptohelper.CreateHMACSHA256(hmac256Key, hmacMsg)

	log.Printf("hmac256hashA hex: %v", cryptohelper.BytesToHex(hmac256hashA))
	log.Printf("hmac256hashA b64: %v", cryptohelper.BytesToBase64(hmac256hashA))
	log.Printf("CompareHMAC: %v", cryptohelper.CompareHMAC(hmac256hashA, hmac256hashB))

	hmac512hashA := cryptohelper.CreateHMACSHA512(hmac512Key, hmacMsg)
	hmac512hashB := cryptohelper.CreateHMACSHA512(hmac512Key, hmacMsg)

	log.Printf("hmac512hashA hex: %v", cryptohelper.BytesToHex(hmac512hashA))
	log.Printf("hmac512hashA b64: %v", cryptohelper.BytesToBase64(hmac512hashA))
	log.Printf("CompareHMAC: %v", cryptohelper.CompareHMAC(hmac512hashA, hmac512hashB))
}
