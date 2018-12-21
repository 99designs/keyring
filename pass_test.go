package keyring

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

func setup(t *testing.T) (*passKeyring, func(t *testing.T)) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	tmpdir, err := ioutil.TempDir("", "keyring-pass-test")
	if err != nil {
		t.Fatal(err)
	}

	// Initialise a blank GPG homedir; import & trust the test key
	gnupghome := filepath.Join(tmpdir, ".gnupg")
	os.Mkdir(gnupghome, os.FileMode(int(0700)))
	os.Setenv("GNUPGHOME", gnupghome)
	os.Unsetenv("GPG_AGENT_INFO")
	os.Unsetenv("GPG_TTY")
	cmd := exec.Command("gpg", "--import", filepath.Join(pwd, "testdata", "test-gpg.key"))
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("gpg", "--import-ownertrust", filepath.Join(pwd, "testdata", "test-ownertrust-gpg.txt"))
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}

	passdir := filepath.Join(tmpdir, ".password-store")
	k := &passKeyring{
		dir:     passdir,
		passcmd: "pass",
		prefix:  "aws-vault",
	}

	cmd, err = k.pass("init", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}

	return k, func(t *testing.T) {
		os.RemoveAll(tmpdir)
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

func TestPassKeyringRemove(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatalf(err.Error())
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}
