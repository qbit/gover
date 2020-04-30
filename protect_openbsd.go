package main

import (
	"log"

	"golang.org/x/sys/unix"
)

func pledge(promises string) {
	err := unix.PledgePromises(promises)
	if err != nil {
		log.Fatal(err)
	}
}

func unveil(path string, flags string) {
	err := unix.Unveil(path, flags)
	if err != nil {
		log.Fatal(err)
	}
}

func unveilBlock() {
	err := unix.UnveilBlock()
	if err != nil {
		log.Fatal(err)
	}
}
