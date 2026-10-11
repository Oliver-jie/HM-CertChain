package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	msp "github.com/hyperledger/fabric-protos-go/msp"
	"math/big"
	"testing"
	"time"
)

func makeCA(t *testing.T, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey) (*x509.Certificate, string, *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		var e error
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if e != nil {
		t.Fatal(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}
func invoke(t *testing.T, s *shimtest.MockStub, creator string, args ...string) bool {
	t.Helper()
	sid := &msp.SerializedIdentity{Mspid: "Org1MSP", IdBytes: []byte(creator)}
	b, e := proto.Marshal(sid)
	if e != nil {
		t.Fatal(e)
	}
	s.Creator = b
	a := make([][]byte, len(args))
	for i, v := range args {
		a[i] = []byte(v)
	}
	r := s.MockInvoke("tx-"+args[0], a)
	if r.Status != 200 {
		t.Logf("%v: %s", args[0], r.Message)
		return false
	}
	return true
}
func ident(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func TestMigrationLifecycleAndPermissions(t *testing.T) {
	s := shimtest.NewMockStub("hm", new(Contract))
	root, rootPEM, rootKey := makeCA(t, "root", nil, nil, nil)
	b, bpem, bKey := makeCA(t, "B", root, rootKey, nil)
	_, cpem, cKey := makeCA(t, "C", root, rootKey, nil)
	_, apem, aKey := makeCA(t, "A", b, bKey, nil)
	if !invoke(t, s, "root", "InitializeRoot", "root", rootPEM) {
		t.Fatal("root")
	}
	if !invoke(t, s, "root", "RegisterCA", "B", "root", ident("B"), "Org1MSP", bpem) {
		t.Fatal("B")
	}
	if !invoke(t, s, "root", "RegisterCA", "C", "root", ident("C"), "Org1MSP", cpem) {
		t.Fatal("C")
	}
	if !invoke(t, s, "B", "RegisterCA", "A", "B", ident("A"), "Org1MSP", apem) {
		t.Fatal("A")
	}
	now := time.Now().Unix()
	t1 := now + 1000
	t2 := now + 2000
	fromInt := func(v int64) string { return big.NewInt(v).String() }
	if invoke(t, s, "attacker", "Initialization", "sid", "A", "B", "C", fromInt(t1), fromInt(t2)) {
		t.Fatal("unauthorized initialization accepted")
	}
	if !invoke(t, s, "A", "Initialization", "sid", "A", "B", "C", fromInt(t1), fromInt(t2)) {
		t.Fatal("initialize")
	}
	if invoke(t, s, "C", "Unlock", "sid") {
		t.Fatal("unauthorized Unlock accepted")
	}
	ca, e := new(Contract).getCA(s, "A")
	if e != nil || ca.Parent != "B" {
		t.Fatal("parent changed before authorization")
	}
	if !invoke(t, s, "B", "Unlock", "sid") {
		t.Fatal("unlock")
	}
	ca, e = new(Contract).getCA(s, "A")
	if e != nil || ca.Parent != "B" {
		t.Fatal("parent changed in pending state")
	}
	_, newPEM, _ := makeCA(t, "A", mustCert(t, cpem), cKey, aKey)
	if invoke(t, s, "C", "CommitMigration", "sid", newPEM, hex.EncodeToString(make([]byte, 32))) {
		t.Fatal("out-of-window commit accepted")
	}
	if invoke(t, s, "B", "Execution", "sid") {
		t.Fatal("premature abort accepted")
	}
	// Exercise a successful commit at an explicitly controlled transaction timestamp.
	// The mock's MockInvoke always overwrites its timestamp; call the handler directly.
	sid := &msp.SerializedIdentity{Mspid: "Org1MSP", IdBytes: []byte("C")}
	creatorBytes, err := proto.Marshal(sid)
	if err != nil {
		t.Fatal(err)
	}
	s.Creator = creatorBytes
	s.MockTransactionStart("commit-tx")
	s.TxTimestamp = &timestamp.Timestamp{Seconds: t1 + 1}
	err = new(Contract).commit(s, []string{"sid", newPEM, hex.EncodeToString(make([]byte, 32))})
	s.MockTransactionEnd("commit-tx")
	if err != nil {
		t.Fatalf("valid commit rejected: %v", err)
	}
	ca, err = new(Contract).getCA(s, "A")
	if err != nil || ca.Parent != "C" || ca.ActiveMigration != "" {
		t.Fatal("atomic parent update failed")
	}
	m, err := new(Contract).getMigration(s, "sid")
	if err != nil || m.State != "Committed" || !m.IsRevoked || !m.IsIssued {
		t.Fatal("migration state inconsistent")
	}
}
func mustCert(t *testing.T, p string) *x509.Certificate {
	t.Helper()
	v, e := parseCert(p)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
