//+build !openbsd

package main

func pledge(promises string)           {}
func unveil(path string, flags string) {}
func unveilBlock()                     {}
