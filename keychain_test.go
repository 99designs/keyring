// +build darwin

package keyring

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestOSXKeychainKeyringSet(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(path, t)

	k := &keychain{
		path:         path,
		passwordFunc: fixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v.Data, item.Data)
	}

	if string(v.Key) != item.Key {
		t.Fatalf("Key stored was not the data retrieved: %q vs %q", v.Key, item.Key)
	}

	if string(v.Description) != item.Description {
		t.Fatalf("Description stored was not the data retrieved: %q vs %q", v.Description, item.Description)
	}
}

func TestOSXKeychainKeyringOverwrite(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(path, t)

	k := &keychain{
		path:         path,
		passwordFunc: fixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	item1 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item1); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v1.Data) != string(item1.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item1.Data)
	}

	item2 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item2); err != nil {
		t.Fatal(err)
	}

	v2, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v2.Data) != string(item2.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v2.Data, item2.Data)
	}
}

func TestOSXKeychainKeyringListKeys(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(path, t)

	k := &keychain{
		path:         path,
		service:      "test",
		passwordFunc: fixedStringPrompt("test password"),
		isTrusted:    true,
	}

	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		item := Item{
			Key:  key,
			Data: []byte("llamas are great"),
		}

		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q vs %q", keys, keys2)
	}
}

func TestOSXKeychainKeyringHandlesExpiry(t *testing.T) {
	Debug = true

	path := tempPath()
	defer deleteKeychain(path, t)

	// set a fixed time
	clock := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	k := &keychain{
		path:         path,
		service:      "test",
		passwordFunc: fixedStringPrompt("test password"),
		isTrusted:    false,
		clock:        func() time.Time { return clock },
	}

	item := Item{
		Key:     "test",
		Data:    []byte("llamas are great"),
		Expires: clock.Add(time.Hour),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	var kwe KeyringWithExpiry = k

	k.clock = func() time.Time {
		// add 10 hours, past our expiry date
		return clock.Add(time.Hour * 10)
	}

	expired, err := kwe.IsExpired("test")
	if err != nil {
		t.Fatal(err)
	}

	if !expired {
		t.Fatal("Expected item to be expired")
	}
}

func deleteKeychain(path string, t *testing.T) {
	if _, err := os.Stat(path); os.IsExist(err) {
		os.Remove(path)
	}

	// Sierra introduced a -db suffix
	dbPath := path + "-db"
	if _, err := os.Stat(dbPath); os.IsExist(err) {
		os.Remove(dbPath)
	}
}

func tempPath() string {
	// TODO make filename configurable
	return filepath.Join(os.TempDir(), fmt.Sprintf("keyring-test-%d.keychain", time.Now().UnixNano()))
}
