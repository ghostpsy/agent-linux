//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// readConfirmLine reads one line for [y/N] prompts. Uses /dev/tty when stdin is not the terminal
// (e.g. ghostpsy started from a shell script whose stdin is a pipe).
func readConfirmLine() (string, error) {
	ttyIn, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		var line string
		_, scanErr := fmt.Scanln(&line)
		if scanErr != nil && scanErr != io.EOF {
			return "", scanErr
		}
		return strings.TrimSpace(line), nil
	}
	defer func() { _ = ttyIn.Close() }()
	br := bufio.NewReader(ttyIn)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
