vagrant
=======

This directory contains Vagrant images for use in development and testing.

Using
-----

### Fedora (Gnome desktop)

**Pre-Reqs:**

1. Install vagrant
2. Install vagrant plugins:

```sh
vagrant plugin install vagrant-vbguest
vagrant plugin install vagrant-reload
```

**Launch**:

```sh
cd vagrant/fedora
vagrant up
```

This will launch the fedora VM with a Gnome UI and Gnome Keyring installed.
A full go environment will also be installed. The first `up` may take a while
to install all the packages and reboot at least once. You may want to use
`vagrant halt` instead of `destroy` to suspend the VM until you're done
with dev/test.

The root of the project will be mounted as a host folder to `/src`.

Run tests from an SSH or GUI Terminal session in the fedora VM:

```sh
cd /src
go test -v ./...
```

### Windows 10

**Pre-Reqs:**

1. Install vagrant

**Launch**:

```sh
cd vagrant/windows
vagrant up
```

`git` and `go` will be installed via the chocolately package manager.

A GUI will open up. Login and open cmd or powershell.

The root of the project will be mounted to `C:\src`

```sh
cd C:\src
go test -v .
```