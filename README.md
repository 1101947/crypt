# Crypt
is a simple encryption utility.

# Notice
Not production ready !

# Installation
## Downloading source code
``` sh
git clone https://github.com/1101947/crypt.git
```
## Building:
``` sh
go build -ldflags="-X 'main.IsBuilt=true' -X 'main.Version=v$(date -d "$(git show -s --format=%cI --date=iso-strict HEAD)" -u +"%Y-%m-%d_%H-%M-%SZ")__$(git rev-parse HEAD)'" -o crypt *.go
```
## System installation:
Simply put generated executable "crypt" in current directory in any PATH directory of your liking, for example:
``` sh
cp crypt ~/.local/bin/crypt
```

# Usage
To encrypt file, run:
``` sh
crypt encrypt --input="path-to-the-file-to-encrypt" --output="path-to-the-encrypted-file"
```
To decrypt file, run:
``` sh
crypt decrypt --input="path-to-the-encrypted-file" --output="path-to-the-decrypted-file"
```
# License
This project is licensed uder GPLv3, for more information see LICENSE.txt

# Changelog
This project uses changelog file(see CHANGELOG.md).
Changelog file contains log of changes for each project version(see version section).
It allows users and developers to see what changes have been made in new version, what features have been added and if any bugs or security vulnerabilities was introduced or fixed.
Format was inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unlike keepachangelog.com current version is tagged "current" and don't have a proper version string like all previous versions, we don't use semver(see versioning section), we have additional Bug-introduced and Bug-found types of changes.

# Versioning
This project adheres to so called(by us) commitver: commit versioning scheme.
In this versioning shceme, version is a string, a combination of a timestamp of source code release and its hash.
For example, if version was released at 2026-07-22 16:20:43 and its unique hash string is 100cf2e0284c25e0c9a7c6433ee516409514ad63, the version string will be:
v2026-07-22_16-20-43Z__100cf2e0284c25e0c9a7c6433ee516409514ad63.
Every commit in master branch should contain working code, but to be sure always address to CHANGELOG.md.
To see semantics, added features, introduced and fixed bugs of any version address to CHANGELOG.md.

# TODO:
- Refactor versioning section.
- store hmac/aead in header to verify it(header) and optionaly allow user to use securely stored version to protect from replay attack(replace valid encrypted file with another version of valid encrypted file) 
- add size check(check for number of numbers that chunkPosition can hold, safe amount of data you can encrypt with different nonces and same key for aes256gcm and chacha20poly1305)
- add verification function/method for header and cryptData(crypt.go)
- add option to enable progress bar while en/decrypting
- add tests, try to decrypted tampered files, try to change header bytes and random bytes, see how decryption will go.
- add Verify for argon header. KeyLen must be 32 byte long for both aes256gcm and chacha20poly1305. Remove user flag for setting key length.
