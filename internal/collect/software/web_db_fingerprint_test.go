//go:build linux

package software

import "testing"

func TestReNginxServerTokens(t *testing.T) {
	b := []byte("http { server_tokens off; }\n")
	m := reNginxServerTokens.FindSubmatch(b)
	if len(m) < 2 || string(m[1]) != "off" {
		t.Fatalf("got %q", m)
	}
}

func TestReMysqlBind(t *testing.T) {
	b := []byte("[mysqld]\nbind-address = 127.0.0.1\n")
	m := reMysqlBind.FindSubmatch(b)
	if len(m) < 2 || string(m[1]) != "127.0.0.1" {
		t.Fatalf("got %q", m)
	}
}
