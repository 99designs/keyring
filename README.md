Keyring
=======
[![Build Status](https://github.com/99designs/keyring/workflows/Continuous%20Integration/badge.svg)](https://github.com/99designs/keyring/actions)
[![Documentation](https://godoc.org/github.com/99designs/keyring?status.svg)](https://godoc.org/github.com/99designs/keyring)

Keyring provides utility functions for and a common interface to a range of secure credential storage services. Originally developed as part of [AWS Vault](https://github.com/99designs/aws-vault), a command line tool for securely managing AWS access from developer workstations.

Currently Keyring supports the following backends
  * macOS/OSX Keychain
  * Windows credential store
  * [Pass](https://www.passwordstore.org/)
  * [Secret Service](https://github.com/99designs/aws-vault/pull/98)
  * [KDE Wallet](https://github.com/99designs/aws-vault/pull/27)
  * [Encrypted File](https://github.com/99designs/aws-vault/pull/63)
  * [LastPass](https://github.com/99designs/aws-vault/pull/597)
     * Requires [lastpass-cli](https://github.com/lastpass/lastpass-cli)

## Installing

`go get github.com/99designs/keyring`

## Usage

The short version of how to use keyring is shown below.

```go
ring, _ := keyring.Open(keyring.Config{
  ServiceName: "example",
})

_ = ring.Set(keyring.Item{
	Key: "foo",
	Data: []byte("secret-bar"),
})

i, _ := ring.Get("foo")

fmt.Printf("%s", i.Data)
```

For more detail on the API please check [the keyring godocs](https://godoc.org/github.com/99designs/keyring)

## Development & Contributing

Contributions to the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

This project will adhere to the [Go Community Code of Conduct](https://golang.org/conduct) in the github provided discussion spaces, with the moderators being the 99designs engineering team.

To make a contribution:

  * Fork the repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests
  * Ideally verify that [aws-vault](https://github.com/99designs/aws-vault) works with your changes (optional)

...and we'll do our best to get your work merged in
