module github.com/99designs/keyring

go 1.14

require (
	github.com/danieljoos/wincred v1.0.2
	github.com/dvsekhvalnov/jose2go v0.0.0-20180829124132-7f401d37b68a
	github.com/godbus/dbus/v5 v5.0.4-0.20200214231604-06fc4b473149
	github.com/gsterjov/go-libsecret v0.0.0-00010101000000-000000000000
	github.com/keybase/go-keychain v0.0.0-20190712205309-48d3d31d256d
	github.com/kr/pretty v0.1.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/stretchr/objx v0.2.0 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/sys v0.0.0-20190712062909-fae7ac547cb7 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace github.com/gsterjov/go-libsecret => github.com/mtibben/go-libsecret v0.0.0-20200227032814-7f732c2515e9
