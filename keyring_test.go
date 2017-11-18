package keyring_test

import (
	"log"

	"github.com/99designs/keyring"
)

func ExampleOpen() {
	kr, err := keyring.Open(keyring.Config{
		KeychainName: "my-keychain",
		Backends:     keyring.SupportedBackends(),
	})

	v, err := kr.Get("llamas")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("llamas was %v", v)
}
