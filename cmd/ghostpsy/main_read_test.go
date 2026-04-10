//go:build linux

package main

import (
	"io"
	"strings"
	"testing"
)

func TestReadLimited_Capped(t *testing.T) {
	r := strings.NewReader("abcdefghij")
	out, err := readLimited(r, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "abcd" {
		t.Fatalf("got %q", out)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "efghij" {
		t.Fatalf("underlying reader should retain unread bytes; got %q", rest)
	}
}

func TestReadLimited_FullSmall(t *testing.T) {
	r := strings.NewReader("xy")
	out, err := readLimited(r, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "xy" {
		t.Fatalf("got %q", out)
	}
}
