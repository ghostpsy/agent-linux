//go:build linux

package actionlog

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

const (
	classificationLocalRead   = "local-read-only"
	classificationLocalModify = "local-modifying"
	classificationExternalSend = "external-send"
	classificationCompute     = "local-compute"
)

type Summary struct {
	FilesReadCount        int
	ExternalRequestsCount int
	ExternalDomains       map[string]struct{}
	WriteModifyCount      int
	SystemChangingCount   int
}

type Logger struct {
	enabled bool
	out     io.Writer
	summary Summary
}

func New(enabled bool, out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{
		enabled: enabled,
		out:     out,
		summary: Summary{ExternalDomains: map[string]struct{}{}},
	}
}

func (l *Logger) Enabled() bool {
	return l != nil && l.enabled
}

func (l *Logger) Step(classification, target, message string, fields map[string]string) {
	if !l.Enabled() {
		return
	}
	l.track(classification, target)
	fmt.Fprintf(l.out, "%s%s%s%s\n", colorFor(classification), iconFor(classification), message, colorReset+formatFields(fields))
}

func (l *Logger) Note(message string, fields map[string]string) {
	if !l.Enabled() {
		return
	}
	fmt.Fprintf(l.out, "%s• %s%s%s\n", colorBlue, message, colorReset, formatFields(fields))
}

func (l *Logger) PrintSummary() {
	if !l.Enabled() {
		return
	}
	domains := make([]string, 0, len(l.summary.ExternalDomains))
	for domain := range l.summary.ExternalDomains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	fmt.Fprintln(l.out, "--- Verbose action summary ---")
	fmt.Fprintf(l.out, "files_read_count=%d\n", l.summary.FilesReadCount)
	fmt.Fprintf(l.out, "external_requests_count=%d\n", l.summary.ExternalRequestsCount)
	fmt.Fprintf(l.out, "external_domains=%s\n", strings.Join(domains, ","))
	fmt.Fprintf(l.out, "write_modify_actions_count=%d\n", l.summary.WriteModifyCount)
	fmt.Fprintf(l.out, "system_changing_actions_count=%d\n", l.summary.SystemChangingCount)
	fmt.Fprintln(l.out, "--- End verbose action summary ---")
}

func (l *Logger) track(classification, target string) {
	switch classification {
	case classificationLocalRead:
		l.summary.FilesReadCount++
	case classificationExternalSend:
		l.summary.ExternalRequestsCount++
		if parsedURL, err := url.Parse(target); err == nil && parsedURL.Host != "" {
			l.summary.ExternalDomains[parsedURL.Host] = struct{}{}
		}
	case classificationLocalModify:
		l.summary.WriteModifyCount++
	}
}

func formatFields(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, redactValue(key, fields[key])))
	}
	return " | " + strings.Join(parts, " | ")
}

func redactValue(key, value string) string {
	keyLower := strings.ToLower(strings.TrimSpace(key))
	if strings.Contains(keyLower, "token") || strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "password") || strings.Contains(keyLower, "authorization") || strings.Contains(keyLower, "cookie") || strings.Contains(keyLower, "bearer") {
		return "[REDACTED]"
	}
	return value
}

const colorReset = "\033[0m"
const colorGreen = "\033[32m"
const colorYellow = "\033[33m"
const colorMagenta = "\033[35m"
const colorCyan = "\033[36m"
const colorBlue = "\033[34m"

func colorFor(classification string) string {
	switch classification {
	case classificationLocalRead:
		return colorCyan
	case classificationExternalSend:
		return colorMagenta
	case classificationLocalModify:
		return colorYellow
	default:
		return colorGreen
	}
}

func iconFor(classification string) string {
	switch classification {
	case classificationLocalRead:
		return "READ  "
	case classificationExternalSend:
		return "SEND  "
	case classificationLocalModify:
		return "WRITE "
	default:
		return "WORK  "
	}
}
