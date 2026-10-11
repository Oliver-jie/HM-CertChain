package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hyperledger/fabric/hmcertchain/hoa"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	msp "github.com/hyperledger/fabric-protos-go/msp"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

type CA struct {
	ID              string `json:"id"`
	OwnerID         string `json:"ownerId"`
	MSPID           string `json:"mspId"`
	Parent          string `json:"parent"`
	CertPEM         string `json:"certPem"`
	CertHash        string `json:"certHash"`
	Revoked         bool   `json:"revoked"`
	ActiveMigration string `json:"activeMigration,omitempty"`
}
type Certificate struct {
	ID      string `json:"id"`
	Issuer  string `json:"issuer"`
	PEM     string `json:"pem"`
	Hash    string `json:"hash"`
	Revoked bool   `json:"revoked"`
}
type Migration struct {
	ID              string `json:"id"`
	CAID            string `json:"caId"`
	OldParent       string `json:"oldParent"`
	NewParent       string `json:"newParent"`
	OldHash         string `json:"oldHash"`
	NewHash         string `json:"newHash,omitempty"`
	ProofCommitment string `json:"proofCommitment,omitempty"`
	ProofVerified   bool   `json:"proofVerified"`
	T1              int64  `json:"t1"`
	T2              int64  `json:"t2"`
	IsRevoked       bool   `json:"isRevoked"`
	IsIssued        bool   `json:"isIssued"`
	State           string `json:"migrationState"`
}

type Contract struct{}

func main() {
	if err := shim.Start(new(Contract)); err != nil {
		panic(err)
	}
}
func (*Contract) Init(stub shim.ChaincodeStubInterface) pb.Response { return shim.Success(nil) }
func (c *Contract) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	name, args := stub.GetFunctionAndParameters()
	var out interface{}
	var err error
	switch name {
	case "RegisterHOAAnchor":
		err = c.registerHOAAnchor(stub, args)
	case "GetHOAAnchor":
		out, err = c.getHOAAnchor(stub, arg1(args))
	case "InitializeRoot":
		err = c.initializeRoot(stub, args)
	case "RegisterCA":
		err = c.registerCA(stub, args)
	case "IssueCertificate":
		err = c.issueCertificate(stub, args)
	case "RevokeCertificate":
		err = c.revokeCertificate(stub, args)
	case "Initialization":
		err = c.initialization(stub, args)
	case "Unlock":
		err = c.unlock(stub, args)
	case "Execution":
		err = c.execution(stub, args)
	case "CommitMigration":
		err = c.commit(stub, args)
	case "GetCA":
		out, err = c.getCA(stub, arg1(args))
	case "GetCertificate":
		out, err = c.getCertificate(stub, arg1(args))
	case "GetMigration":
		out, err = c.getMigration(stub, arg1(args))
	case "GetEffectiveParent":
		var ca *CA
		ca, err = c.getCA(stub, arg1(args))
		if err == nil {
			out = map[string]string{"caId": ca.ID, "effectiveParent": ca.Parent}
		}
	default:
		return shim.Error("unknown function: " + name)
	}
	if err != nil {
		return shim.Error(err.Error())
	}
	if out == nil {
		return shim.Success(nil)
	}
	b, e := json.Marshal(out)
	if e != nil {
		return shim.Error(e.Error())
	}
	return shim.Success(b)
}
func arg1(a []string) string {
	if len(a) != 1 {
		return ""
	}
	return a[0]
}
func expect(a []string, n int) error {
	if len(a) != n {
		return fmt.Errorf("expected %d arguments, got %d", n, len(a))
	}
	for _, v := range a {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("empty argument")
		}
	}
	return nil
}
func key(t, id string) string { return t + ":" + id }
func read(stub shim.ChaincodeStubInterface, t, id string, d interface{}) error {
	if id == "" {
		return fmt.Errorf("identifier required")
	}
	b, e := stub.GetState(key(t, id))
	if e != nil {
		return e
	}
	if b == nil {
		return fmt.Errorf("%s %s does not exist", t, id)
	}
	return json.Unmarshal(b, d)
}
func save(stub shim.ChaincodeStubInterface, t, id string, d interface{}) error {
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	return stub.PutState(key(t, id), b)
}
func missing(stub shim.ChaincodeStubInterface, t, id string) error {
	b, e := stub.GetState(key(t, id))
	if e != nil {
		return e
	}
	if b != nil {
		return fmt.Errorf("duplicate %s: %s", t, id)
	}
	return nil
}
func (c *Contract) getCA(s shim.ChaincodeStubInterface, id string) (*CA, error) {
	v := new(CA)
	e := read(s, "ca", id, v)
	return v, e
}
func (c *Contract) getMigration(s shim.ChaincodeStubInterface, id string) (*Migration, error) {
	v := new(Migration)
	e := read(s, "migration", id, v)
	return v, e
}
func (c *Contract) getCertificate(s shim.ChaincodeStubInterface, id string) (*Certificate, error) {
	v := new(Certificate)
	e := read(s, "certificate", id, v)
	return v, e
}
func identity(s shim.ChaincodeStubInterface) (string, string, error) {
	creator, e := s.GetCreator()
	if e != nil {
		return "", "", e
	}
	var sid msp.SerializedIdentity
	if e = proto.Unmarshal(creator, &sid); e != nil {
		return "", "", e
	}
	if sid.Mspid == "" || len(sid.IdBytes) == 0 {
		return "", "", fmt.Errorf("missing creator identity")
	}
	h := sha256.Sum256(sid.IdBytes)
	return hex.EncodeToString(h[:]), sid.Mspid, nil
}
func checkOwner(s shim.ChaincodeStubInterface, ca *CA) error {
	id, m, e := identity(s)
	if e != nil {
		return e
	}
	if id != ca.OwnerID || m != ca.MSPID {
		return fmt.Errorf("transaction invoker is not the authorized owner of CA %s", ca.ID)
	}
	if ca.Revoked {
		return fmt.Errorf("CA revoked")
	}
	return nil
}
func parseCert(pemString string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
func hashCert(c *x509.Certificate) string { h := sha256.Sum256(c.Raw); return hex.EncodeToString(h[:]) }
func verifyCA(child, parent *x509.Certificate, now time.Time) error {
	if !child.IsCA || child.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("CA certificate missing CA key usage")
	}
	if now.Before(child.NotBefore) || now.After(child.NotAfter) {
		return fmt.Errorf("CA certificate outside validity period")
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("invalid issuer signature: %w", err)
	}
	return nil
}
func txTime(s shim.ChaincodeStubInterface) (time.Time, error) {
	t, e := s.GetTxTimestamp()
	if e != nil {
		return time.Time{}, e
	}
	if t == nil {
		return time.Time{}, fmt.Errorf("missing tx timestamp")
	}
	return time.Unix(t.Seconds, int64(t.Nanos)).UTC(), nil
}
func (c *Contract) initializeRoot(s shim.ChaincodeStubInterface, a []string) error {
	if e := expect(a, 2); e != nil {
		return e
	}
	if e := missing(s, "config", "root"); e != nil {
		return e
	}
	if e := missing(s, "ca", a[0]); e != nil {
		return e
	}
	id, m, e := identity(s)
	if e != nil {
		return e
	}
	cert, e := parseCert(a[1])
	if e != nil {
		return e
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if e = verifyCA(cert, cert, now); e != nil {
		return e
	}
	ca := CA{ID: a[0], OwnerID: id, MSPID: m, CertPEM: a[1], CertHash: hashCert(cert)}
	if e = save(s, "ca", a[0], ca); e != nil {
		return e
	}
	return s.PutState(key("config", "root"), []byte(a[0]))
}
func (c *Contract) registerCA(s shim.ChaincodeStubInterface, a []string) error {
	// id, parentID, ownerID, ownerMSP, PEM certificate
	if e := expect(a, 5); e != nil {
		return e
	}
	if e := missing(s, "ca", a[0]); e != nil {
		return e
	}
	parent, e := c.getCA(s, a[1])
	if e != nil {
		return e
	}
	if e = checkOwner(s, parent); e != nil {
		return e
	}
	p, e := parseCert(parent.CertPEM)
	if e != nil {
		return e
	}
	cert, e := parseCert(a[4])
	if e != nil {
		return e
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if e = verifyCA(cert, p, now); e != nil {
		return e
	}
	return save(s, "ca", a[0], CA{ID: a[0], Parent: a[1], OwnerID: a[2], MSPID: a[3], CertPEM: a[4], CertHash: hashCert(cert)})
}
func (c *Contract) issueCertificate(s shim.ChaincodeStubInterface, a []string) error {
	if e := expect(a, 3); e != nil {
		return e
	}
	if e := missing(s, "certificate", a[0]); e != nil {
		return e
	}
	issuer, e := c.getCA(s, a[1])
	if e != nil {
		return e
	}
	if e = checkOwner(s, issuer); e != nil {
		return e
	}
	ic, e := parseCert(issuer.CertPEM)
	if e != nil {
		return e
	}
	cert, e := parseCert(a[2])
	if e != nil {
		return e
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if cert.IsCA {
		return fmt.Errorf("use RegisterCA for CA certificates")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired or not yet valid")
	}
	if e = cert.CheckSignatureFrom(ic); e != nil {
		return e
	}
	return save(s, "certificate", a[0], Certificate{ID: a[0], Issuer: a[1], PEM: a[2], Hash: hashCert(cert)})
}
func (c *Contract) revokeCertificate(s shim.ChaincodeStubInterface, a []string) error {
	if e := expect(a, 1); e != nil {
		return e
	}
	cert, e := c.getCertificate(s, a[0])
	if e != nil {
		return e
	}
	issuer, e := c.getCA(s, cert.Issuer)
	if e != nil {
		return e
	}
	if e = checkOwner(s, issuer); e != nil {
		return e
	}
	if cert.Revoked {
		return fmt.Errorf("already revoked")
	}
	cert.Revoked = true
	return save(s, "certificate", cert.ID, cert)
}
func (c *Contract) initialization(s shim.ChaincodeStubInterface, a []string) error {
	// sessionID, CA-ID, old parent, new parent, t1, t2
	if e := expect(a, 6); e != nil {
		return e
	}
	if e := missing(s, "migration", a[0]); e != nil {
		return e
	}
	ca, e := c.getCA(s, a[1])
	if e != nil {
		return e
	}
	if e = checkOwner(s, ca); e != nil {
		return e
	}
	if ca.ActiveMigration != "" {
		return fmt.Errorf("active migration exists")
	}
	if ca.Parent == "" || ca.Parent != a[2] || a[2] == a[3] || a[1] == a[3] {
		return fmt.Errorf("invalid parent transition")
	}
	old, e := c.getCA(s, a[2])
	if e != nil {
		return e
	}
	newParent, e := c.getCA(s, a[3])
	if e != nil {
		return e
	}
	if old.Revoked || newParent.Revoked {
		return fmt.Errorf("parent CA revoked")
	}
	// prevent cycles: destination must not be a descendant of migrating CA
	seen := map[string]bool{}
	walk := newParent
	for {
		if walk.ID == ca.ID {
			return fmt.Errorf("migration creates trust cycle")
		}
		if seen[walk.ID] {
			return fmt.Errorf("existing CA hierarchy contains a cycle")
		}
		seen[walk.ID] = true
		if walk.Parent == "" {
			break
		}
		walk, e = c.getCA(s, walk.Parent)
		if e != nil {
			return e
		}
	}
	t1, e := strconv.ParseInt(a[4], 10, 64)
	if e != nil {
		return e
	}
	t2, e := strconv.ParseInt(a[5], 10, 64)
	if e != nil {
		return e
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if !(now.Unix() < t1 && t1 < t2) {
		return fmt.Errorf("must satisfy t0 < t1 < t2")
	}
	v := Migration{ID: a[0], CAID: ca.ID, OldParent: old.ID, NewParent: newParent.ID, OldHash: ca.CertHash, T1: t1, T2: t2, State: "Normal"}
	ca.ActiveMigration = v.ID
	if e = save(s, "migration", v.ID, v); e != nil {
		return e
	}
	return save(s, "ca", ca.ID, ca)
}
func (c *Contract) unlock(s shim.ChaincodeStubInterface, a []string) error {
	if e := expect(a, 1); e != nil {
		return e
	}
	v, e := c.getMigration(s, a[0])
	if e != nil {
		return e
	}
	if v.State != "Normal" {
		return fmt.Errorf("migration not in Normal state")
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if now.Unix() >= v.T1 {
		return fmt.Errorf("revocation authorization window expired")
	}
	parent, e := c.getCA(s, v.OldParent)
	if e != nil {
		return e
	}
	if e = checkOwner(s, parent); e != nil {
		return e
	}
	ca, e := c.getCA(s, v.CAID)
	if e != nil {
		return e
	}
	if ca.Parent != v.OldParent || ca.CertHash != v.OldHash || ca.ActiveMigration != v.ID {
		return fmt.Errorf("migration certificate or parent changed")
	}
	v.IsRevoked = true
	v.State = "Pending"
	return save(s, "migration", v.ID, v)
}
func (c *Contract) commit(s shim.ChaincodeStubInterface, a []string) error {
	// session ID, new CA certificate PEM, external HOA-CH proof commitment
	if e := expect(a, 3); e != nil {
		return e
	}
	v, e := c.getMigration(s, a[0])
	if e != nil {
		return e
	}
	if v.State != "Pending" || !v.IsRevoked {
		return fmt.Errorf("migration not prepared")
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	if now.Unix() <= v.T1 || now.Unix() >= v.T2 {
		return fmt.Errorf("commit outside time window")
	}
	parent, e := c.getCA(s, v.NewParent)
	if e != nil {
		return e
	}
	if e = checkOwner(s, parent); e != nil {
		return e
	}
	ca, e := c.getCA(s, v.CAID)
	if e != nil {
		return e
	}
	if ca.ActiveMigration != v.ID || ca.Parent != v.OldParent || ca.CertHash != v.OldHash {
		return fmt.Errorf("migration state no longer matches")
	}
	cert, e := parseCert(a[1])
	if e != nil {
		return e
	}
	p, e := parseCert(parent.CertPEM)
	if e != nil {
		return e
	}
	if e = verifyCA(cert, p, now); e != nil {
		return e
	}
	oldCert, e := parseCert(ca.CertPEM)
	if e != nil {
		return e
	}
	if string(cert.RawSubject) != string(oldCert.RawSubject) {
		return fmt.Errorf("certificate subject must be preserved")
	}
	if string(cert.RawSubjectPublicKeyInfo) != string(oldCert.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("CA public key must be preserved")
	}
	// Commit requires a live on-ledger HOA anchor bound to the pre-migration certificate.
	anchor, e := c.getHOAAnchor(s, ca.ID)
	if e != nil {
		return fmt.Errorf("HOA anchor missing: %w", e)
	}
	if anchor.CertificateHash != v.OldHash {
		return fmt.Errorf("HOA anchor not bound to original certificate")
	}
	var proof AdaptationProof
	if e = json.Unmarshal([]byte(a[2]), &proof); e != nil {
		return fmt.Errorf("invalid adaptation proof JSON: %w", e)
	}
	if proof.SessionID != v.ID || proof.CAID != v.CAID {
		return fmt.Errorf("proof session mismatch")
	}
	group, pk, hash, oldR, e := anchor.numbers()
	if e != nil {
		return e
	}
	newR, e := parseNumber(proof.NewRandomness)
	if e != nil {
		return e
	}
	oldPath := []byte(v.OldParent + "/" + v.CAID)
	newPath := []byte(v.NewParent + "/" + v.CAID)
	if !hoa.VerifyAdapt(group, pk, oldCert.Raw, oldPath, cert.Raw, newPath, hash, oldR, newR) {
		return fmt.Errorf("HOA adaptation proof verification failed")
	}
	sum := sha256.Sum256([]byte(a[2]))
	proofDigest := hex.EncodeToString(sum[:])
	anchor.Randomness = proof.NewRandomness
	anchor.CertificateHash = hashCert(cert)
	anchor.TrustParent = v.NewParent
	if e = save(s, "hoa-anchor", ca.ID, anchor); e != nil {
		return e
	}

	ca.Parent = parent.ID
	ca.CertPEM = a[1]
	ca.CertHash = hashCert(cert)
	ca.ActiveMigration = ""
	v.NewHash = ca.CertHash
	v.ProofCommitment = proofDigest
	v.ProofVerified = true
	v.IsIssued = true
	v.State = "Committed"
	if e = save(s, "ca", ca.ID, ca); e != nil {
		return e
	}
	return save(s, "migration", v.ID, v)
}
func (c *Contract) execution(s shim.ChaincodeStubInterface, a []string) error {
	if e := expect(a, 1); e != nil {
		return e
	}
	v, e := c.getMigration(s, a[0])
	if e != nil {
		return e
	}
	if v.State == "Aborted" || v.State == "Committed" {
		return nil
	}
	now, e := txTime(s)
	if e != nil {
		return e
	}
	deadline := v.T2
	if v.State == "Normal" {
		deadline = v.T1
	}
	if now.Unix() < deadline {
		return fmt.Errorf("deadline not reached")
	}
	ca, e := c.getCA(s, v.CAID)
	if e != nil {
		return e
	}
	if ca.ActiveMigration != v.ID {
		return fmt.Errorf("unexpected migration lock")
	}
	ca.ActiveMigration = ""
	v.State = "Aborted"
	if e = save(s, "ca", ca.ID, ca); e != nil {
		return e
	}
	return save(s, "migration", v.ID, v)
}
