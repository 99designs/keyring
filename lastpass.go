package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type lastPassKeyring struct {
	lpasscmd string
	folder   string
}

func init() {
	supportedBackends[LastPassBackend] = opener(func(cfg Config) (Keyring, error) {
		lpass := &lastPassKeyring{
			lpasscmd: cfg.LastPassCmd,
			folder:   cfg.LastPassFolder,
		}

		if cfg.LastPassCmd == "" {
			lpass.lpasscmd = "lpass"
		}

		if cfg.LastPassFolder == "" {
			lpass.folder = "aws-vault"
		}

		_, err := exec.LookPath(lpass.lpasscmd)
		if err != nil {
			return nil, fmt.Errorf("The %s program is not available", lpass.lpasscmd)
		}

		return lpass, nil
	})
}

func (k *lastPassKeyring) lpass(args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(k.lpasscmd, args...)

	cmd.Stderr = os.Stderr

	return cmd, nil
}

func (k *lastPassKeyring) Get(key string) (Item, error) {
	name := fmt.Sprintf("%s/%s", k.folder, key)
	cmd, err := k.lpass("show", "--sync=now", "--notes", name)

	if err != nil {
		return Item{}, err
	}

	output, err := cmd.Output()
	if err != nil {
		return Item{}, err
	}

	var decoded Item
	err = json.Unmarshal(output, &decoded)

	return decoded, err
}

func (k *lastPassKeyring) GetMetadata(key string) (Metadata, error) {
	return Metadata{}, nil
}

func (k *lastPassKeyring) Set(i Item) error {
	bytes, err := json.Marshal(i)
	if err != nil {
		return err
	}

	name := fmt.Sprintf("%s/%s", k.folder, i.Key)
	cmd, err := k.lpass("edit", "--sync=now", "--notes", "--non-interactive", name)
	if err != nil {
		return err
	}

	cmd.Stdin = strings.NewReader(string(bytes))

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (k *lastPassKeyring) Remove(key string) error {
	name := filepath.Join(k.folder, key)
	cmd, err := k.lpass("rm", "--sync=now", name)
	if err != nil {
		return err
	}

	err = cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

func (k *lastPassKeyring) Keys() ([]string, error) {
	var keys = []string{}

	cmd, err := k.lpass("ls", "--sync=now", "--format=%an", "--color=never", k.folder)
	if err != nil {
		return keys, err
	}

	output, err := cmd.Output()
	if err != nil {
		return keys, err
	}

	keys = strings.Split(string(output), "\n")

	return keys, nil
}
