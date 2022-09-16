//go:build darwin && cgo
// +build darwin,cgo

package keyring

import (
	"errors"
	"fmt"
	"os"

	gokeychain "github.com/99designs/go-keychain"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/lox/go-touchid"
)

const (
	touchIDLabel = "Passphrase for %s"
)

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool

	isTouchIDAuthenticated bool
	useTouchID             bool
	touchIDAccount         string
	touchIDService         string
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		kc := &keychain{
			service:      cfg.ServiceName,
			passwordFunc: cfg.KeychainPasswordFunc,

			// Set the isAccessibleWhenUnlocked to the boolean value of
			// KeychainAccessibleWhenUnlocked is a shorthand for setting the accessibility value.
			// See: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
			isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,

			isTouchIDAuthenticated: false,
		}
		if cfg.UseBiometrics {
			switch {
			case cfg.TouchIDAccount == "":
				return kc, fmt.Errorf("TouchIDAccount must be non-empty if UseBiometrics is true")

			case cfg.TouchIDService == "":
				return kc, fmt.Errorf("TouchIDService must be non-empty if UseBiometrics is true")
			}

			kc.useTouchID = true
			kc.touchIDAccount = cfg.TouchIDAccount
			kc.touchIDService = cfg.TouchIDService
		}
		if cfg.KeychainName != "" {
			kc.path = cfg.KeychainName + ".keychain"
		}
		if cfg.KeychainTrustApplication {
			kc.isTrusted = true
		}
		return kc, nil
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
		// When we are querying, we don't create by default
		query.SetMatchSearchList(gokeychain.NewWithPath(k.path))
	}

	debugf("Querying keychain for service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *keychain) GetMetadata(key string) (Metadata, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(false)
	query.SetReturnRef(true)

	debugf("Querying keychain for metadata of service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	} else if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
	}

	md := Metadata{
		Item: &Item{
			Key:         key,
			Label:       results[0].Label,
			Description: results[0].Description,
		},
		ModificationTime: results[0].ModificationDate,
	}

	debugf("Found metadata for %q", md.Item.Label)

	return md, nil
}

func (k *keychain) updateItem(kc gokeychain.Keychain, kcItem gokeychain.Item, account string) error {
	queryItem := gokeychain.NewItem()
	queryItem.SetSecClass(gokeychain.SecClassGenericPassword)
	queryItem.SetService(k.service)
	queryItem.SetAccount(account)
	queryItem.SetMatchLimit(gokeychain.MatchLimitOne)
	queryItem.SetReturnAttributes(true)

	if k.path != "" {
		queryItem.SetMatchSearchList(kc)
	}

	results, err := gokeychain.QueryItem(queryItem)
	if err != nil {
		return fmt.Errorf("Failed to query keychain: %v", err)
	}
	if len(results) == 0 {
		return errors.New("no results")
	}

	// Don't call SetAccess() as this will cause multiple prompts on update, even when we are not updating the AccessList
	kcItem.SetAccess(nil)

	if err := gokeychain.UpdateItem(queryItem, kcItem); err != nil {
		return fmt.Errorf("Failed to update item in keychain: %v", err)
	}

	return nil
}

func (k *keychain) Set(item Item) error {
	var kc gokeychain.Keychain

	// when we are setting a value, we create or open
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

	if k.isSynchronizable && !item.KeychainNotSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	isTrusted := k.isTrusted && !item.KeychainNotTrustApplication

	if isTrusted {
		debugf("Keychain item trusts keyring")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: nil,
		})
	} else {
		debugf("Keychain item doesn't trust keyring")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: []string{},
		})
	}

	debugf("Adding service=%q, label=%q, account=%q, trusted=%v to osx keychain %q", k.service, item.Label, item.Key, isTrusted, k.path)

	err := gokeychain.AddItem(kcItem)

	if err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, updating")
		err = k.updateItem(kc, kcItem, item.Key)
	}

	if err != nil {
		return err
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
			if err == gokeychain.ErrorNoSuchKeychain {
				return ErrKeyNotFound
			}
			return err
		}

		item.SetMatchSearchList(kc)
	}

	debugf("Removing keychain item service=%q, account=%q, keychain %q", k.service, key, k.path)
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
			if err == gokeychain.ErrorNoSuchKeychain {
				return []string{}, nil
			}
			return nil, err
		}

		query.SetMatchSearchList(kc)
	}

	debugf("Querying keychain for service=%q, keychain=%q", k.service, k.path)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	debugf("Found %d results", len(results))
	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	debugf("Checking keychain status")
	err := kc.Status()
	if err == nil {
		if k.useTouchID {
			return k.openWithTouchID()
		}
		debugf("Keychain status returned nil, keychain exists")
		return kc, nil
	}

	debugf("Keychain status returned error: %v", err)

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

func (k *keychain) openWithTouchID() (gokeychain.Keychain, error) {
	if k.isTouchIDAuthenticated {
		// already unlocked, return keychain
		return gokeychain.NewWithPath(k.path), nil
	}

	debugf("checking with touchid")
	ok, err := touchid.Authenticate("unlock " + k.path)
	if err != nil {
		return gokeychain.Keychain{}, fmt.Errorf("failed to authenticate with biometrics: %v", err)
	}
	if !ok {
		return gokeychain.Keychain{}, fmt.Errorf("failed to authenticate with biometrics")
	}

	k.isTouchIDAuthenticated = true

	debugf("looking up %s password in login.keychain", k.path)
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.touchIDService)
	query.SetAccount(k.touchIDAccount)
	query.SetLabel(fmt.Sprintf(touchIDLabel, k.path))
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return gokeychain.Keychain{}, fmt.Errorf("failed to query keychain: %v", err)
	}

	var passphrase string
	if len(results) != 1 {
		// touch ID was never set up, let's do it now
		var err error
		passphrase, err = k.setupTouchID()
		if err != nil {
			return gokeychain.Keychain{}, fmt.Errorf("failed to setup touchid: %v", err)
		}
	} else {
		debugf("found password in login.keychain, unlocking %s with stored password", k.path)
		passphrase = string(results[0].Data)

		// try unlocking with the passphrase we found
		if err := gokeychain.UnlockAtPath(k.path, passphrase); err != nil {
			return gokeychain.Keychain{}, fmt.Errorf("failed to unlock keychain: %v", err)
		}
	}
	// either way we've unlocked the keychain so we should be able to return it

	return gokeychain.NewWithPath(k.path), nil
}

func (k *keychain) setupTouchID() (string, error) {
	fmt.Printf("\nTo use Touch ID for authentication, the aws-vault keychain password needs to be stored in your login keychain.\n" +
		"You will be prompted for the password you use to unlock aws-vault.\n\n")

	var passphrase string
	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		fmt.Printf("Password for %q: ", k.path)
		passphraseBytes, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %v", err)
		}

		passphrase = string(passphraseBytes)
	} else {
		var err error
		passphrase, err = k.passwordFunc(fmt.Sprintf("Enter passphrase for %q", k.path))
		if err != nil {
			return "", fmt.Errorf("failed to get password: %v", err)
		}
	}

	fmt.Println()
	debugf("locking keychain %s", k.path)
	if err := gokeychain.LockAtPath(k.path); err != nil {
		return "", fmt.Errorf("failed to lock keychain: %v", err)
	}

	debugf("unlocking keychain %s", k.path)
	if err := gokeychain.UnlockAtPath(k.path, passphrase); err != nil {
		return "", fmt.Errorf("failed to unlock keychain: %v", err)
	}

	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.touchIDService)
	item.SetAccount(k.touchIDAccount)
	item.SetLabel(fmt.Sprintf(touchIDLabel, k.path))
	item.SetData([]byte(passphrase))
	item.SetSynchronizable(gokeychain.SynchronizableNo)
	item.SetAccessible(gokeychain.AccessibleWhenUnlocked)

	debugf("Adding service=%q, account=%q to osx keychain %s", k.touchIDService, k.touchIDAccount, k.path)
	if err := gokeychain.AddItem(item); err != nil {
		return "", fmt.Errorf("failed to add item to keychain: %v", err)
	}

	return passphrase, nil
}
