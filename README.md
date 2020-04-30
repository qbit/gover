gover
=====

`gover` lets you easily install and test other versions of Go. Think `gotip`
but for releases!

`gover` also verifies PGP signatures for downloaded release tarballs.

## Install
```
go get suah.dev/gover
```

## Example run
```
qbit@litr /t/hello_go> gover download 1.13.9
Fetching "https://dl.google.com/go/go1.13.9.src.tar.gz"
Fetching "https://dl.google.com/go/go1.13.9.src.tar.gz.asc"
Signature OK.
extracted tarball into /home/qbit/sdk/gover/1.13.9: 8687 files, 1089 dirs (4.804680289s)
Building Go cmd/dist using /usr/local/go.
Building Go toolchain1 using /usr/local/go.
Building Go bootstrap cmd/go (go_bootstrap) using Go toolchain1.
Building Go toolchain2 using go_bootstrap and Go toolchain1.
Building Go toolchain3 using go_bootstrap and Go toolchain2.
Building packages and commands for openbsd/amd64.
---
Installed Go for openbsd/amd64 in /home/qbit/sdk/gover/1.13.9/go
Installed commands in /home/qbit/sdk/gover/1.13.9/go/bin
Success. You may now run 'gover 1.13.9'!
qbit@litr /t/hello_go> gover 1.13.9 build
qbit@litr /t/hello_go> goversion ./hello_go 
./hello_go go1.13.9
qbit@litr /t/hello_go> go build
qbit@litr /t/hello_go> goversion ./hello_go
./hello_go go1.14.2
qbit@litr /t/hello_go> 
```
