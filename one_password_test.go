//go:build darwin && cgo
// +build darwin,cgo

package keyring_test

import (
	"os/exec"
	"reflect"
	"sort"
	"testing"

	"github.com/99designs/keyring"
)

func deleteTestVault() {
	exec.Command("op", "vault", "delete", "one_password_test").Run()
}

func setup(t *testing.T) keyring.Keyring {
	t.Helper()
	t.Cleanup(deleteTestVault)
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:   []keyring.BackendType{keyring.OnePasswordBackend},
		OnePasswordPrefix: "Test",
		OnePasswordVault:  "one_password_test",
	})

	if err != nil {
		t.Fatal(err)
	}

	exec.Command("op", "vault", "create", "one_password_test").Run()

	return kr
}

func TestOnePasswordKeyringSet(t *testing.T) {
	kr := setup(t)
	item := keyring.Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}

func TestOnePasswordKeyringOverwrite(t *testing.T) {
	kr := setup(t)

	item1 := keyring.Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := kr.Set(item1); err != nil {
		t.Fatal(err)
	}

	v1, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v1.Data) != string(item1.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item1.Data)
	}

	item2 := keyring.Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := kr.Set(item2); err != nil {
		t.Fatal(err)
	}

	v2, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v2.Data) != string(item2.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v2.Data, item2.Data)
	}
}

func TestOnePasswordKeyringListKeysWhenEmpty(t *testing.T) {
	kr := setup(t)

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestOnePasswordKeyringListKeysWhenNotEmpty(t *testing.T) {
	kr := setup(t)

	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		item := keyring.Item{
			Key:  key,
			Data: []byte("llamas are great"),
		}

		if err := kr.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}

	sort.Strings(keys)
	sort.Strings(keys2)

	if !reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q vs %q", keys, keys2)
	}
}

func TestOnePasswordGetKeyWhenEmpty(t *testing.T) {
	kr := setup(t)

	_, err := kr.Get("no-such-key")
	if err != keyring.ErrKeyNotFound {
		t.Fatal("expected ErrKeyNotFound")
	}
}

func TestOnePasswordGetKeyWhenNotEmpty(t *testing.T) {
	kr := setup(t)

	item := keyring.Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	v1, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if string(v1.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item.Data)
	}
}

func TestOnePasswordRemoveKeyWhenEmpty(t *testing.T) {
	kr := setup(t)

	err := kr.Remove("no-such-key")
	if err != keyring.ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOnePasswordRemoveKeyWhenNotEmpty(t *testing.T) {
	kr := setup(t)

	item := keyring.Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	_, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	err = kr.Remove("llamas")
	if err != nil {
		t.Fatal(err)
	}
}
