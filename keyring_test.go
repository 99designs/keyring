package keyring

import "testing"

func TestItemsEqual(t *testing.T) {
	i := Item{
		Key: "key",
		Data: []byte("data"),
		Label: "label",
		Description: "description",
		KeychainNotTrustApplication: false,
		KeychainNotSynchronizable: false,
	}

	// We're basically going to create copies of i and make sure each field difference generates a false return value
	// from Equals.

	// First, make sure identity is true.
	o := i
	if !i.Equals(o) {
		t.Fatalf("identity case should result in true")
	}

	// Test key differences
	o.Key = "something else"
	if i.Equals(o) {
		t.Fatalf("key difference should result in false")
	}

	// Test key differences
	o = i
	o.Data = []byte("something else")
	if i.Equals(o) {
		t.Fatalf("data difference should result in false")
	}

	// Test label differences
	o = i
	o.Label = "something else"
	if i.Equals(o) {
		t.Fatalf("label difference should result in false")
	}

	// Test description differences
	o = i
	o.Description = "something else"
	if i.Equals(o) {
		t.Fatalf("description difference should result in false")
	}

	// Test KeychainNotTrustApplication differences
	o = i
	o.KeychainNotTrustApplication = true
	if i.Equals(o) {
		t.Fatalf("KeyChainNotTrustApplication difference should result in false")
	}

	// Test KeychainNotSynchronizable differences
	o = i
	o.KeychainNotSynchronizable = true
	if i.Equals(o) {
		t.Fatalf("KeyChainNotSynchronizable difference should result in false")
	}
}
