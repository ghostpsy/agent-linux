//go:build linux

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	lipTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	lipSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	lipError   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	lipMuted   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

func printSectionTitle(w io.Writer, title string) {
	_, _ = fmt.Fprintln(w, lipTitle.Render(title))
}

func printSuccessLine(msg string) {
	fmt.Println(lipSuccess.Render(msg))
}

func printMutedLine(msg string) {
	fmt.Println(lipMuted.Render(msg))
}

func printErrorLine(msg string) {
	fmt.Fprintln(os.Stderr, lipError.Render(msg))
}
