# jagile fork with OS X keychain and password prompt!

# Checkpoint Firewall Login

Command line agent for checkpoint firewall authentication

# Install

Download the [latest release](https://github.com/felixb/cpfw-login/releases/latest).
Make sure to pick the right OS.

# Usage

Run the agent on your command line like this:
```
    ./cpfw-login --url <cp fw url> --user <username> --password <password>
```
or save your password in the keychain with `--osx-save-password` and use it later.


The following parameters are available:

 * `--url` // `CPFW_AUTH_URL` required: base url of your checkpoint firewall login form without '/PortalMain'
 * `--user` // `CPFW_AUTH_USER` required: your user name
 * `--password` // `CPFW_AUTH_PASSWORD` required: your password
 * `--check` // `CPFW_AUTH_CHECK_URL` optional: any http url, used for checking before and after login. should be behind your firewall.
 * `--interval` optional: recheck/relogin every X seconds
 * `--insecure` optional: don't verify SSL/TLS connections
 * `--osx-save-password` optional: save provided password into (encrypted) OS X keychain to use it next time
 * `--prompt-password` optional: prompt passwort from the terminal

## How can I avoid plain text password in my shell history?

```
    ./cpfw-login --prompt-password ...
```
## How can I avoid to manually provide the password each time (I have OS X)?

```
    ./cpfw-login --prompt-password --osx-save-password ...
```

## Can I use keychain on Linux?

There is a cross-plattform implementation (https://github.com/tmc/keyring), one can use it as well with a different option (like `--linux-save-password`). The current implementation (https://github.com/keybase/go-keychain) uses native OS X call to allow access control to the saved password only for the `cpfw-login` binary as apposed to generally callable tool `/usr/bin/security`.

# Build

```
  go get
  go build
```
# Contributing

 1. fork
 2. commit
 3. send PR
