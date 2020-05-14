// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// The gover command compiles and runs the go command from a release version.
//
// To install, run:
//
//     $ go get suah.dev/gover
//     $ gover download 1.14.2
//
// And then use the gover command as if it were your normal go command.
//
// To download a specific version, run "gover download VERSION".
package main

import (
	"bytes"
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

	"golang.org/x/crypto/openpgp"
	"suah.dev/protect"
)

// Google Inc. (Linux Packages Signing Authority) <linux-packages-keymaster@google.com>
// RSA key 0x78BD65473CB3BD13
// Primary key fingerprint: EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796
// Subkey fingerprint:      2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13
const pubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=kkJT
-----END PGP PUBLIC KEY BLOCK-----
`

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

	_, err = openpgp.CheckArmoredDetachedSignature(kr, tbz, sig)
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
