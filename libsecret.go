// +build linux

package keyring

import (
	"encoding/json"
	"errors"

	"github.com/godbus/dbus/v5"
	libsecret "github.com/ppacher/go-dbus-keyring"
)

func init() {
	conn, err := dbus.SessionBus()
	if err != nil {
		// silently fail if dbus isn't available
		return
	}

	supportedBackends[SecretServiceBackend] = opener(func(cfg Config) (Keyring, error) {
		if cfg.ServiceName == "" {
			cfg.ServiceName = "secret-service"
		}
		if cfg.LibSecretCollectionName == "" {
			cfg.LibSecretCollectionName = cfg.ServiceName
		}

		service, err := libsecret.GetSecretService(conn)
		if err != nil {
			return &secretsKeyring{}, err
		}

		ring := &secretsKeyring{
			name:    cfg.LibSecretCollectionName,
			service: service,
		}

		return ring, ring.openSecrets()
	})
}

type secretsKeyring struct {
	name       string
	service    libsecret.SecretService
	collection libsecret.Collection
	session    libsecret.Session
}

type secretsError struct {
	message string
}

func (e *secretsError) Error() string {
	return e.message
}

var errCollectionNotFound = errors.New("The collection does not exist. Please add a key first")

func (k *secretsKeyring) openSecrets() error {
	var err error
	k.session, err = k.service.OpenSession()
	if err != nil {
		return err
	}

	// get the collection if it already exists
	k.collection, err = k.service.GetCollection(k.name)
	if err.Error() == "unknown collection" {
		k.collection = nil
		return nil
	}

	return err
}

func (k *secretsKeyring) openCollection() error {
	if err := k.openSecrets(); err != nil {
		return err
	}

	if k.collection == nil {
		return errCollectionNotFound
	}

	return nil
}

func (k *secretsKeyring) Get(key string) (Item, error) {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	item, err := k.collection.GetItem(key)
	if err != nil {
		return Item{}, err
	}

	locked, err := item.Locked()
	if err != nil {
		return Item{}, err
	}

	if locked {
		ok, err := item.Unlock()
		if err != nil {
			return Item{}, err
		}
		if !ok {
			return Item{}, errors.New("Couldn't unlock item")
		}
	}

	secret, err := item.GetSecret(k.session.Path())
	if err != nil {
		return Item{}, err
	}

	// pack the secret into the item
	var ret Item
	if err = json.Unmarshal(secret.Value, &ret); err != nil {
		return Item{}, err
	}

	return ret, err
}

// GetMetadata for libsecret returns an error indicating that it's unsupported
// for this backend.
//
// libsecret actually implements a metadata system which we could use, "Secret
// Attributes"; I found no indication in documentation of anything like an
// automatically maintained last-modification timestamp, so to use this we'd
// need to have a SetMetadata API too.  Which we're not yet doing, but feel
// free to contribute patches.
func (k *secretsKeyring) GetMetadata(key string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

func (k *secretsKeyring) Set(item Item) error {
	err := k.openSecrets()
	if err != nil {
		return err
	}

	// create the collection if it doesn't already exist
	if k.collection == nil {
		collection, err := k.service.CreateCollection(k.name, "")
		if err != nil {
			return err
		}

		k.collection = collection
	}

	if err := k.ensureCollectionUnlocked(); err != nil {
		return err
	}

	// create the new item
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}

	if _, err := k.collection.CreateItem(k.session.Path(), item.Key, map[string]string{}, data, "application/json", true); err != nil {
		return err
	}

	return nil
}

func (k *secretsKeyring) Remove(key string) error {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return ErrKeyNotFound
		}
		return err
	}

	item, err := k.collection.GetItem(key)
	if err != nil {
		return err
	}

	locked, err := item.Locked()
	if err != nil {
		return err
	}

	if locked {
		ok, err := item.Unlock()
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("Couldn't unlock item")
		}
	}

	if err := item.Delete(); err != nil {
		return err
	}

	return nil
}

func (k *secretsKeyring) Keys() ([]string, error) {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return []string{}, nil
		}
		return nil, err
	}
	if err := k.ensureCollectionUnlocked(); err != nil {
		return nil, err
	}
	items, err := k.collection.GetAllItems()
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for _, item := range items {
		label, err := item.GetLabel()
		if err == nil {
			keys = append(keys, label)
		} else {
			// err is being silently ignored here, not sure if that's good or bad
		}
	}
	return keys, nil
}

// deleteCollection deletes the keyring's collection if it exists. This is mainly to support testing.
func (k *secretsKeyring) deleteCollection() error {
	if err := k.openCollection(); err != nil {
		return err
	}
	return k.collection.Delete()
}

// unlock the collection if it's locked
func (k *secretsKeyring) ensureCollectionUnlocked() error {
	locked, err := k.collection.Locked()
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}

	_, err = k.service.Unlock([]dbus.ObjectPath{k.collection.Path()})

	return err
}
