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
Unlike Keep a Changelog, current version is tagged "current" and don't have a proper version string like all previous versions, we don't use [semver](https://semver.org/spec/v2.0.0.html)(see versioning section), we have additional Bug-introduced and Bug-found types of changes.

# Versioning
This project adheres to so called(by us) commitver: commit versioning scheme.
In this versioning shceme, version is a string, a combination of a timestamp of source code release and its hash.
For example, if version was released at 2026-07-22 16:20:43 and its unique hash string is 100cf2e0284c25e0c9a7c6433ee516409514ad63, the version string will be:
v2026-07-22_16-20-43Z__100cf2e0284c25e0c9a7c6433ee516409514ad63.
Every commit in master branch should contain working code, but to be sure always address to CHANGELOG.md.
To see semantics, added features, introduced and fixed bugs of any version address to CHANGELOG.md.

# TODO:
- Consider safe feature: allow to set file offset for C.In in cryptofile.(En/De)crypt function. The problem is that if you have writen to \*os.File and then try to read, you will get EOF, because \*os.File offset is equal to filesize and when you start reading it will start reading from the end, obviously will read 0 bytes and will return EOF. So in order to prevent or control this standard behavior default offset will be set to 0 and before reading file Seek(offset(which is 0 by default), 0) will be performed. 
- Test against end of file(in chunk, salt, nonce).
- Refactor versioning section.
- store hmac/aead in header to verify it(header) and optionaly allow user to use securely stored version to protect from replay attack(replace valid encrypted file with another version of valid encrypted file) 
- add size check(check for number of numbers that chunkPosition can hold, safe amount of data you can encrypt with different nonces and same key for aes256gcm and chacha20poly1305)
- add option to enable progress bar while en/decrypting
- add tests, try to decrypted tampered files, try to change header bytes and random bytes, see how decryption will go.
- Add description of file format
- Add option for automaticly generating encrypted files with file format extension(like .enc or .crt or .crpt)(option is disabled by default)
- add CONTRIBUTING.md
- add SECURITY.md
- add canary warrant
- add progress bar
- interactive mode(enter function you want to encrypt file with: \<aes/chacha\>:)
- shell autocompletion
- add function: header dumper
- add function: partial/query crypter(decrypt only 1 3 52 chunks, mb latter when will have extended format with table)
- add function: reencrypter(to reencrypt without decrypting and having decrypted file just laying around on disk, free to see for everyone) 
- add: stdio encryption 
- add: getting and passing files via ipc(unix domain socket with fd(sock_setqpacket) passing, creation of in-memory file and passing its descriptor( memfd_create + scm_rights), pipes)
- add: extended format with table(or merkle tree) at the end(like zip)(will allow to store chunks metadata and use it for managing passowrd or other uses)
- add: deniable encryption
- add: totp
- add: one time pad
- set up exit codes
- add: ability to seat units for bytes sizes(64KB, 1MB) and use arithmetics(--memory=1024\*1024kb)
- shorten --input and --output flags to --in and --out
- Shorten crypt encrypt and crypt decrypt to:
    crypt en 
    crypt de
- Different variants for passing required arguments:
    crypt en --input=f.txt --output=f.enc
    Or 
    crypt en f.txt f.en
- Cli parsing:
    - error if unknow flag
    - parsing: flag have method Parse(kwargs) which may consist of choosing one of may flag based on following strateges: kwargs.OnlyOne() , kwargs.First(), kwargs.Last(), then just parse string -> needed_type
- add Documentation:
    - generate help messages
    - generate documentation for users and developers
    - add help command that will query and print documentation 
