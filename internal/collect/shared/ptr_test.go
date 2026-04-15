package shared

import "testing"

func TestStringPtr(t *testing.T) {
	t.Parallel()
	s := "hello"
	p := StringPtr(s)
	if p == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *p != "hello" {
		t.Fatalf("got %q, want %q", *p, "hello")
	}
}

func TestStringPtr_empty(t *testing.T) {
	t.Parallel()
	p := StringPtr("")
	if p == nil {
		t.Fatal("expected non-nil pointer")
	}
	if *p != "" {
		t.Fatalf("got %q, want empty string", *p)
	}
}

func TestBoolPtr(t *testing.T) {
	t.Parallel()
	cases := []bool{true, false}
	for _, v := range cases {
		p := BoolPtr(v)
		if p == nil {
			t.Fatalf("BoolPtr(%v): expected non-nil", v)
		}
		if *p != v {
			t.Fatalf("BoolPtr(%v): got %v", v, *p)
		}
	}
}

func TestIntPtr(t *testing.T) {
	t.Parallel()
	cases := []int{0, -1, 42, 1<<31 - 1}
	for _, v := range cases {
		p := IntPtr(v)
		if p == nil {
			t.Fatalf("IntPtr(%d): expected non-nil", v)
		}
		if *p != v {
			t.Fatalf("IntPtr(%d): got %d", v, *p)
		}
	}
}

func TestStringPtr_independentCopies(t *testing.T) {
	t.Parallel()
	a := StringPtr("x")
	b := StringPtr("x")
	if a == b {
		t.Fatal("expected distinct pointers for separate calls")
	}
}
