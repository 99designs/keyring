package keyring

import "testing"

func TestSetAndGets(t *testing.T) {
	k := newMemoryKeyring()

	// Set a few items and try to retrieve them
	items := []Item{
		makeItem("key1", "data1", "label1", "description1"),
		makeItem("key2", "data2", "label2", "description2"),
		makeItem("key3", "data3", "label3", "description3"),
		makeItem("key4", "data4", "label4", "description4"),
	}

	for _, item := range items {
		k.Set(item)
	}

	for _, item := range items {
		getItem, _ := k.Get(item.Key)

		if !item.Equals(getItem) {
			t.Fatalf("%s is not equal to its version from the store", item.Key)
		}
	}

	if _, err := k.Get("non-existent key"); err != ErrKeyNotFound {
		t.Fatalf("error for non-existent key should have been key not found, was: %v", err)
	}
}

func TestRemove(t *testing.T) {
	k := newMemoryKeyring()

	item := makeItem("key1", "data1", "label1", "description1")

	k.Set(item)

	if _, err := k.Get(item.Key); err != nil {
		t.Fatalf("unable to find stored item")
	}

	k.Remove(item.Key)

	if _, err := k.Get(item.Key); err == nil {
		t.Fatalf("after removal, should not have been able to find item")
	}
}

func TestKeys(t *testing.T) {
	k := newMemoryKeyring()

	items := []Item{
		makeItem("key1", "data1", "label1", "description1"),
		makeItem("key2", "data2", "label2", "description2"),
		makeItem("key3", "data3", "label3", "description3"),
		makeItem("key4", "data4", "label4", "description4"),
	}

	for _, item := range items {
		k.Set(item)
	}

	keys, _ := k.Keys()
	for _, item := range items {
		foundKey := false

		for _, key := range keys {
			if item.Key == key	 {
				foundKey = true
				break
			}
		}

		if !foundKey {
			t.Errorf("unable to find key %s", item.Key)
		}
	}
}

func makeItem(key, data, label, description string) Item {
	return Item{
		Key: key,
		Data: []byte(data),
		Label: label,
		Description: description,
	}
}
