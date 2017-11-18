package keyring

type Config struct {
	// Backends is an ordered list of backends to try. Nil means all available
	Backends []BackendType

	// KeychainServiceName is the name of the keychain service used
	KeychainServiceName string

	// MacOSKeychainNameKeychainName is the name of the macOS keychain that is used.
	KeychainName string

	// KeychainTrustApplication is whether the calling application should be trusted by default by items
	KeychainTrustApplication bool

	// KeychainSynchronizable is whether the item can be synchronized to iCloud
	KeychainSynchronizable bool

	// KeychainAccessibleWhenUnlocked is whether the item is accessible when the device is locked
	KeychainAccessibleWhenUnlocked bool

	// KeychainPasswordFunc is an optional function used to prompt the user for a password
	KeychainPasswordFunc PromptFunc

	// FilePasswordFunc is a required function used to prompt the user for a password
	FilePasswordFunc PromptFunc

	// FileDir is the directory that keyring files are stored in, ~ is resolved to home dir
	FileDir string

	// KWalletServiceName is the name of the service that KWallet uses
	KWalletServiceName string

	// KWalletAppID is the application id for KWallet
	KWalletAppID string

	// KWalletFolder is the folder for KWallet
	KWalletFolder string

	// LibSecretCollectionName is the name collection in secret-service
	LibSecretCollectionName string
}

func NewConfig() Config {
	return Config{}
}

func (cfg Config) WithServiceName(name string) Config {
	cfg.KeychainName = name
	cfg.KWalletServiceName = name
	cfg.LibSecretCollectionName = name
	return cfg
}

func (cfg Config) chooseBackend() (BackendType, error) {
	for _, backend := range cfg.Backends {
		if _, ok := supportedBackends[backend]; ok {
			return backend, nil
		}
	}
	return InvalidBackend, ErrNoAvailImpl
}
