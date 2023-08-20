//go:build darwin && cgo
// +build darwin,cgo

package keyring

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func init() {
	supportedBackends[OnePasswordBackend] = opener(func(cfg Config) (Keyring, error) {
		return &onePasswordKeyring{
			account: cfg.OnePasswordAccount,
			vault:   cfg.OnePasswordVault,
			prefix:  cfg.OnePasswordPrefix,
		}, nil
	})
}

type onePasswordKeyring struct {
	account string
	vault   string
	prefix  string
}

type onePasswordField struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

type onePasswordItem struct {
	Id        string             `json:"id"`
	Fields    []onePasswordField `json:"fields,omitempty"`
	Title     string             `json:"title"`
	UpdatedAt time.Time          `json:"updated_at"`
}

const onePasswordKeyNotFoundFragmentMessage = "isn't an item"
const onePasswordItemCategory = "Secure Note"
const onePasswordItemField = "notesPlain"

func (k *onePasswordKeyring) retrieveOnePasswordItem(key string) (onePasswordItem, error) {
	args := []string{
		"item",
		"get",
		k.prefix + key,
		"--format=json",
	}

	if k.account != "" {
		args = append(args, "--account", k.account)
	}

	if k.vault != "" {
		args = append(args, "--vault", k.vault)
	}

	cmd := exec.Command("op", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if strings.Contains(string(output), onePasswordKeyNotFoundFragmentMessage) {
			return onePasswordItem{}, ErrKeyNotFound
		}

		return onePasswordItem{}, err
	}

	var decoded onePasswordItem
	err = json.Unmarshal(output, &decoded)

	return decoded, err
}

func (k *onePasswordKeyring) Get(key string) (Item, error) {
	onePasswordItem, err := k.retrieveOnePasswordItem(key)

	if err != nil {
		return Item{}, err
	}

	var value string
	for _, field := range onePasswordItem.Fields {
		if field.Id == onePasswordItemField {
			value = field.Value
			break
		}
	}

	item := Item{
		Key:   strings.TrimPrefix(onePasswordItem.Title, k.prefix),
		Data:  []byte(fmt.Sprintf("%v", value)),
		Label: strings.TrimPrefix(onePasswordItem.Title, k.prefix),
	}
	return item, nil
}

func (k *onePasswordKeyring) GetMetadata(key string) (Metadata, error) {
	onePasswordItem, err := k.retrieveOnePasswordItem(key)

	if err != nil {
		return Metadata{}, err
	}

	metadata := Metadata{
		ModificationTime: onePasswordItem.UpdatedAt,
	}

	return metadata, nil
}

func (k *onePasswordKeyring) Set(i Item) error {
	k.Remove(i.Key)

	args := []string{
		"item",
		"create",
	}

	if k.account != "" {
		args = append(args, "--account", k.account)
	}

	if k.vault != "" {
		args = append(args, "--vault", k.vault)
	}

	args = append(args, "--category", onePasswordItemCategory)
	args = append(args, "--title", k.prefix+i.Key)

	if i.Label != "" {
		args = append(args, fmt.Sprintf("%s=%s", "label", i.Label))
	}

	if i.Description != "" {
		args = append(args, fmt.Sprintf("%s=%s", "Description", i.Description))
	}

	args = append(args, fmt.Sprintf("%s=%s", onePasswordItemField, string(i.Data)))

	return exec.Command("op", args...).Run()
}

func (k *onePasswordKeyring) Remove(key string) error {
	output, err := exec.Command("op", "item", "delete", k.prefix+key).CombinedOutput()

	if err != nil && strings.Contains(string(output), onePasswordKeyNotFoundFragmentMessage) {
		return ErrKeyNotFound
	}

	return err
}

func (k *onePasswordKeyring) Keys() ([]string, error) {
	args := []string{
		"item",
		"list",
		"--format=json",
	}

	if k.account != "" {
		args = append(args, "--account", k.account)
	}

	if k.vault != "" {
		args = append(args, "--vault", k.vault)
	}

	output, err := exec.Command("op", args...).CombinedOutput()

	if err != nil {
		if strings.Contains(string(output), onePasswordKeyNotFoundFragmentMessage) {
			return nil, ErrKeyNotFound
		}

		return nil, err
	}

	var decoded []onePasswordItem
	err = json.Unmarshal(output, &decoded)

	if err != nil {
		return nil, err
	}

	keys := []string{}
	for _, item := range decoded {
		keys = append(keys, strings.TrimPrefix(item.Title, k.prefix))
	}

	return keys, nil
}
