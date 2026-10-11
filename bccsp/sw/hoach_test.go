package sw

import (
	"math/big"
	"testing"
)

func TestHOARoundTrip(t *testing.T) {
	// INSECURE tiny parameters used strictly for unit tests.
	p, e := NewHOAParameters(big.NewInt(23), big.NewInt(11), big.NewInt(2))
	if e != nil {
		t.Fatal(e)
	}
	key, e := HOAAuthSetup(p, "ca-a")
	if e != nil {
		t.Fatal(e)
	}
	h, r, e := HOAHash(p, key.Public, []byte("original certificate"), []byte("B/A"))
	if e != nil {
		t.Fatal(e)
	}
	if !HOAVerify(p, key.Public, []byte("original certificate"), []byte("B/A"), h, r) {
		t.Fatal("initial Verify failed")
	}
	r2, e := HOAAdapt(p, key, []byte("original certificate"), []byte("B/A"), []byte("new certificate"), []byte("C/A"), h, r)
	if e != nil {
		t.Fatal(e)
	}
	if !HOAVerify(p, key.Public, []byte("new certificate"), []byte("C/A"), h, r2) {
		t.Fatal("adapted Verify failed")
	}
	if !HOATrace(p, key.Public, []byte("original certificate"), []byte("B/A"), []byte("new certificate"), []byte("C/A"), h, r, r2) {
		t.Fatal("trace transcript failed")
	}
	if HOAVerify(p, key.Public, []byte("tampered"), []byte("C/A"), h, r2) {
		t.Fatal("tampered message accepted")
	}
}
