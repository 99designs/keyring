package keyring

import (
	"sync"
)

func init() {
	supportedBackends[MemoryBackend] = opener(func(cfg Config) (Keyring, error) {
		memory := newMemoryKeyring()

		return memory, nil
	})
}

type memoryKeyring struct {
	mutex sync.RWMutex
	mapStore map[string]Item
}

func newMemoryKeyring() *memoryKeyring {
	return &memoryKeyring{
		mutex: sync.RWMutex{},
		mapStore: map[string]Item{},
	}
}

func (k *memoryKeyring) Get(key string) (Item, error) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	if item, ok := k.mapStore[key]; !ok {
		return Item{}, ErrKeyNotFound
	} else {
		return item, nil
	}
}

// GetMetadata for memory returns an error indicating that it's unsupported
// for this backend.
//
// It doesn't really apply to the memory backend, as it's a simple wrapper around a map.
func (k *memoryKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrNoAvailImpl
}

func (k *memoryKeyring) Set(item Item) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	k.mapStore[item.Key] = item
	return nil
}

func (k *memoryKeyring) Remove(key string) error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	delete(k.mapStore, key)
	return nil
}

func (k *memoryKeyring) Keys() ([]string, error) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	keys := []string{}
	for k := range k.mapStore {
		keys = append(keys, k)
	}
	return keys, nil
}
