// +build linux

package keyring

import (
	"sort"
	"testing"

	"github.com/godbus/dbus/v5"
	libsecret "github.com/ppacher/go-dbus-keyring"
)

func libSecretSetup(t *testing.T) (Keyring, func(t *testing.T)) {
	conn, err := dbus.SessionBus()

	if err != nil {
		t.Fatal(err)
	}

	service, err := libsecret.GetSecretService(conn)
	if err != nil {
		t.Fatal(err)
	}
	kr := &secretsKeyring{
		name:    "keyring-test",
		service: service,
	}
	return kr, func(t *testing.T) {
		if err := kr.deleteCollection(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLibSecretKeysWhenEmpty(t *testing.T) {
	kr, _ := libSecretSetup(t)

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestLibSecretKeysWhenNotEmpty(t *testing.T) {
	kr, teardown := libSecretSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}
	item2 := Item{Key: "alpacas", Data: []byte("alpacas are better")}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := kr.Set(item2); err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys, got %d", len(keys))
	}

	sort.Strings(keys)
	if keys[0] != "alpacas" {
		t.Fatalf("Expected alpacas")
	}
	if keys[1] != "llamas" {
		t.Fatalf("Expected llamas")
	}
}

func TestLibSecretGetWhenEmpty(t *testing.T) {
	kr, _ := libSecretSetup(t)

	_, err := kr.Get("llamas")
	if err != ErrKeyNotFound {
		t.Fatalf("Expected ErrKeyNotFound, got: %s", err)
	}
}

func TestLibSecretGetWhenNotEmpty(t *testing.T) {
	kr, teardown := libSecretSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	it, err := kr.Get(item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if it.Key != item.Key {
		t.Fatal("Expected item not returned")
	}
}

func TestLibSecretRemoveWhenEmpty(t *testing.T) {
	kr, _ := libSecretSetup(t)

	err := kr.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("Expected ErrKeyNotFound, got: %s", err)
	}
}

func TestLibSecretRemoveWhenNotEmpty(t *testing.T) {
	kr, teardown := libSecretSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}

	if _, err := kr.Get("llamas"); err != nil {
		t.Fatal(err)
	}

	if err := kr.Remove("llamas"); err != nil {
		t.Fatal(err)
	}
}
