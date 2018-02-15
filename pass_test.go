package keyring

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func setup(t *testing.T) (*passKeyring, func(t *testing.T)) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	gnupghome := filepath.Join(pwd, "testdata", "gnupghome")
	os.Chmod(gnupghome, os.FileMode(int(0700)))
	os.Setenv("GNUPGHOME", gnupghome)
	os.Unsetenv("GPG_AGENT_INFO")
	os.Unsetenv("GPG_TTY")

	dir, err := ioutil.TempDir("", "keyring-pass-test")
	if err != nil {
		t.Fatal(err)
	}

	k := &passKeyring{
		dir:     dir,
		passcmd: "pass",
		prefix:  "aws-vault/",
	}

	cmd, err := k.pass("init", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}

	return k, func(t *testing.T) {
		os.RemoveAll(dir)
	}
}

func TestPassKeyringSetWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get("llamas")
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

func TestPassKeyringKeysWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %q", len(keys))
	}
}

func TestPassKeyringKeysWhenNotEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	item = Item{Key: "alpacas", Data: []byte("alpacas are better")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 {
		t.Fatalf("Expected 0 keys, got %q", len(keys))
	}

	sort.Strings(keys)
	if keys[0] != "alpacas" {
		t.Fatalf("Expected alpacas")
	}
	if keys[1] != "llamas" {
		t.Fatalf("Expected llamas")
	}
}
