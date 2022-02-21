// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// The gover command compiles and runs the go command from a release version.
//
// To install, run:
//
//     $ go install suah.dev/gover@latest
//     $ gover download 1.14.2
//     $ alias go='gover 1.14.2'
//     $ go version
//     $ go version go1.14.2 openbsd/amd64
//     $
//
// And then use the gover command as if it were your normal go command.
//
// To download a specific version, run "gover download VERSION".
package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"suah.dev/protect"
)

// Google Inc. (Linux Packages Signing Authority) <linux-packages-keymaster@google.com>
// RSA key 0x78BD65473CB3BD13
// Primary key fingerprint: EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796
// Subkey fingerprint:      2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13
//go:embed google.pub
var pubKey string

func main() {
	log.SetFlags(0)
	root, err := goroot("gover")
	version := ""
	if err != nil {
		log.Fatalf("gover: %v", err)
	}

	if err := os.MkdirAll(root, 0755); err != nil {
		log.Fatalf("failed to create gover directory: %v\n", err)
	}

	_ = protect.Pledge("stdio tty unveil rpath cpath wpath proc dns inet fattr exec")

	_ = protect.Unveil("/etc", "r")
	_ = protect.Unveil(root, "rwxc")
	_ = protect.UnveilBlock()

	if len(os.Args) == 1 {
		log.Fatalf("gover: usage: gover [download|version|list]")
		os.Exit(1)
	}

	if os.Args[1] == "download" {
		switch len(os.Args) {
		case 3:
			version = os.Args[2]
			if err := installVer(root, version); err != nil {
				log.Fatalf("gover: %v", err)
			}
		default:
			log.Fatalf("gover: usage: gover download [version]")
		}
		log.Printf("Success. You may now run 'gover %s'!", version)
		os.Exit(0)
	}

	if os.Args[1] == "list" {
		entries, err := os.ReadDir(root)
		if err != nil {
			log.Fatalln(err)
		}
		for _, entry := range entries {
			fmt.Println(entry.Name())
		}
		os.Exit(0)
	}
	version = os.Args[1]
	gobin := filepath.Join(root, version, "go", "bin", "go"+exe())
	gorootPath := filepath.Join(root, version, "go")
	if _, err := os.Stat(gobin); err != nil {
		log.Fatalf("gover: not downloaded. Run 'gover download' to install to %v", root)
	}
	cmd := exec.Command(gobin, os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	newPath := filepath.Join(root, version, "go", "bin")
	if p := os.Getenv("PATH"); p != "" {
		newPath += string(filepath.ListSeparator) + p
	}
	cmd.Env = dedupEnv(caseInsensitiveEnv, append(os.Environ(), "GOROOT="+gorootPath, "PATH="+newPath))
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// TODO: return the same exit status maybe.
			os.Exit(1)
		}
		log.Fatalf("gover: failed to execute %v: %v", gobin, err)
	}
	os.Exit(0)
}
func fetch(a, b string) (*os.File, error) {
	fmt.Printf("Fetching %q\n", a)
	f, err := os.Create(b)
	if err != nil {
		return nil, err
	}

	fResp, err := http.Get(a)
	if err != nil {
		return nil, err
	}

	defer fResp.Body.Close()

	if _, err := io.Copy(f, fResp.Body); err != nil {
		return nil, err
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	return f, nil
}
func fetchify(goURL string, fp string) error {
	var pkt *packet.Config
	buf := bytes.NewBufferString(pubKey)
	kr, err := openpgp.ReadArmoredKeyRing(buf)
	if err != nil {
		return err
	}

	tbz, err := fetch(goURL, fp)
	if err != nil {
		return err
	}
	sig, err := fetch(goURL+".asc", fp+".asc")
	if err != nil {
		return err
	}

	defer tbz.Close()
	defer sig.Close()

	_, err = openpgp.CheckArmoredDetachedSignature(kr, tbz, sig, pkt)
	if err != nil {
		return err
	}

	fmt.Println("Signature OK.")

	_, err = tbz.Seek(0, 0)
	if err != nil {
		return err
	}

	return Untar(tbz, path.Dir(fp))
}
func installVer(root, version string) error {
	goURL := fmt.Sprintf("https://dl.google.com/go/go%s.src.tar.gz", version)
	goFP := filepath.Join(root, version, fmt.Sprintf("go%s.src.tar.gz", version))

	if _, err := os.Stat(filepath.Join(root, version, "go")); err != nil {
		if err := os.MkdirAll(filepath.Join(root, version), 0755); err != nil {
			return fmt.Errorf("failed to create source directory: %v", err)
		}

		err := fetchify(goURL, goFP)
		if err != nil {
			return fmt.Errorf("failed to verify: %v", err)
		}
	}

	cmd := exec.Command(filepath.Join(root, version, "go", "src", makeScript()))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Join(root, version, "go", "src")
	if runtime.GOOS == "windows" {
		// Workaround make.bat not autodetecting GOROOT_BOOTSTRAP. Issue 28641.
		goroot, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			return fmt.Errorf("failed to detect an existing go installation for bootstrap: %v", err)
		}
		cmd.Env = append(os.Environ(), "GOROOT_BOOTSTRAP="+strings.TrimSpace(string(goroot)))
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build go: %v", err)
	}
	return nil
}
func makeScript() string {
	switch runtime.GOOS {
	case "plan9":
		return "make.rc"
	case "windows":
		return "make.bat"
	default:
		return "make.bash"
	}
}

const caseInsensitiveEnv = runtime.GOOS == "windows"

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
func goroot(version string) (string, error) {
	home, err := homedir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}
	return filepath.Join(home, "sdk", version), nil
}
func homedir() (string, error) {
	// This could be replaced with os.UserHomeDir, but it was introduced too
	// recently, and we want this to work with go as packaged by Linux
	// distributions. Note that user.Current is not enough as it does not
	// prioritize $HOME. See also Issue 26463.
	switch runtime.GOOS {
	case "plan9":
		if dir := os.Getenv("home"); dir != "" {
			return dir, nil
		}
		return "", errors.New("can't find user home directory; %USERPROFILE% is empty")
	case "windows":
		if dir := os.Getenv("USERPROFILE"); dir != "" {
			return dir, nil
		}
		return "", errors.New("can't find user home directory; %USERPROFILE% is empty")
	default:
		if dir := os.Getenv("HOME"); dir != "" {
			return dir, nil
		}
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
		return "", errors.New("can't find user home directory; $HOME is empty")
	}
}

// dedupEnv returns a copy of env with any duplicates removed, in favor of
// later values.
// Items are expected to be on the normal environment "key=value" form.
// If caseInsensitive is true, the case of keys is ignored.
//
// This function is unnecessary when the binary is
// built with Go 1.9+, but keep it around for now until Go 1.8
// is no longer seen in the wild in common distros.
//
// This is copied verbatim from golang.org/x/build/envutil.Dedup at CL 10301
// (commit a91ae26).
func dedupEnv(caseInsensitive bool, env []string) []string {
	out := make([]string, 0, len(env))
	saw := map[string]int{} // to index in the array
	for _, kv := range env {
		eq := strings.Index(kv, "=")
		if eq < 1 {
			out = append(out, kv)
			continue
		}
		k := kv[:eq]
		if caseInsensitive {
			k = strings.ToLower(k)
		}
		if dupIdx, isDup := saw[k]; isDup {
			out[dupIdx] = kv
		} else {
			saw[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}
