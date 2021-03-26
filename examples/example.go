package examples

import (
	"github.com/99designs/keyring"
	"log"
)

// ExampleOpen is an example of how you would create a new keyring and how you would
// retrieve data from it.
func ExampleOpen() {
	// Use the best keyring implementation for your operating system
	kr, err := keyring.Open(keyring.Config{
		ServiceName: "my-service",
	})

	v, err := kr.Get("llamas")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("llamas was %v", v)
}

