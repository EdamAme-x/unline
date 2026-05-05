package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadYesNo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "yes", in: "y\n", want: true},
		{name: "long yes", in: "yes\n", want: true},
		{name: "no", in: "n\n", want: false},
		{name: "retry", in: "maybe\ny\n", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readYesNo(bufio.NewReader(strings.NewReader(tt.in)), "prompt")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShellValueEmpty(t *testing.T) {
	if got := shellValue(""); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}
