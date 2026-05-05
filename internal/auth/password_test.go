package auth

import "testing"

func TestHashAndVerifySecret(t *testing.T) {
	hash, err := HashSecret([]byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySecret(hash, []byte("pass")) {
		t.Fatal("expected password to verify")
	}
	if VerifySecret(hash, []byte("wrong")) {
		t.Fatal("wrong password verified")
	}
}
