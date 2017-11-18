// +build darwin

package keyring

import (
	"fmt"
	"log"

	gokeychain "github.com/keybase/go-keychain"
)

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		return &keychain{
			service:      cfg.KeychainServiceName,
			path:         cfg.KeychainName + ".keychain",
			passwordFunc: cfg.KeychainPasswordFunc,
		}, nil
	})
}

func (k *keychain) Get(key string) (Item, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)

	if k.path != "" {
		kc, err := k.createOrOpen()
		if err != nil {
			return Item{}, err
		}

		query.SetMatchSearchList(kc)
	}

	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	return item, nil
}

func (k *keychain) Set(item Item) error {
	var kc gokeychain.Keychain

	if k.path != "" {
		var err error
		kc, err = k.createOrOpen()
		if err != nil {
			return err
		}
	}

	kcItem := gokeychain.NewItem()
	kcItem.SetSecClass(gokeychain.SecClassGenericPassword)
	kcItem.SetService(k.service)
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)

	if k.path != "" {
		kcItem.UseKeychain(kc)
	}

	if k.isSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	kcItem.SetAccess(&gokeychain.Access{
		Label:         item.Label,
		SelfUntrusted: !k.isTrusted,
	})

	debugf("Adding service=%q, label=%q, account=%q to osx keychain %s", k.service, item.Label, item.Key, k.path)
	if err := gokeychain.AddItem(kcItem); err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, deleting")
		delItem := gokeychain.NewItem()
		delItem.SetSecClass(gokeychain.SecClassGenericPassword)
		delItem.SetService(k.service)
		delItem.SetAccount(item.Key)

		if k.path != "" {
			delItem.SetMatchSearchList(kc)
		}

		if err = gokeychain.DeleteItem(delItem); err != nil {
			return fmt.Errorf("Error deleting existing item: %v", err)
		}

		return gokeychain.AddItem(kcItem)
	}

	return nil
}

func (k *keychain) Remove(key string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	item.SetAccount(key)

	if k.path != "" {
		kc := gokeychain.NewWithPath(k.path)

		if err := kc.Status(); err != nil {
			return err
		}

		item.SetMatchSearchList(kc)
	}

	log.Printf("Removing keychain item service=%q, account=%q from osx keychain %q", k.service, key, k.path)
	return gokeychain.DeleteItem(item)
}

func (k *keychain) Keys() ([]string, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	if k.path != "" {
		kc := gokeychain.NewWithPath(k.path)

		if err := kc.Status(); err != nil {
			return nil, err
		}

		query.SetMatchSearchList(kc)
	}

	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	err := kc.Status()
	if err == nil {
		return kc, nil
	}

	if err != gokeychain.ErrorNoSuchKeychain {
		return gokeychain.Keychain{}, err
	}

	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		return gokeychain.NewKeychainWithPrompt(k.path)
	}

	passphrase, err := k.passwordFunc("Enter passphrase for keychain")
	if err != nil {
		return gokeychain.Keychain{}, err
	}

	debugf("Creating keychain %s with provided password", k.path)
	return gokeychain.NewKeychain(k.path, passphrase)
}
