package keyring_test

import (
	"fmt"

	"github.com/99designs/keyring"
)

func ExampleKeyringGet() {
	// Imagine instead this was a keyring.Open("example", keyring.KeychainBackend)
	var ring keyring.Keyring = keyring.NewArrayKeyring([]keyring.Item{
		keyring.Item{
			Key:  "foo",
			Data: []byte("secret-bar"),
		},
	})

	i, err := ring.Get("foo")

	if err == nil {
		fmt.Printf("%s", i.Data)
	}

	// Output: secret-bar
}
