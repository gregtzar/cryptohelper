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
	log.Printf("len: %v", len(cryptohelper.BytesToBase64(key256C)))

	plaintext := "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit."
	log.Printf("plaintext: %v", plaintext)

	cipherbytes, err := cryptohelper.EncryptTextAESGCM(key256A, []byte(plaintext))
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := cryptohelper.BytesToBase64(cipherbytes)
	log.Printf("ciphertext: %v", ciphertext)

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

}
