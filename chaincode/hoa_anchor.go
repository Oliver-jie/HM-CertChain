package main

import (
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric/hmcertchain/hoa"
	"math/big"
)

type HOAAnchor struct {
	CAID            string `json:"caId"`
	CertificateHash string `json:"certificateHash"`
	TrustParent     string `json:"trustParent"`
	P               string `json:"p"`
	Q               string `json:"q"`
	G               string `json:"g"`
	Public          string `json:"public"`
	Hash            string `json:"hash"`
	Randomness      string `json:"randomness"`
}
type AdaptationProof struct {
	SessionID     string `json:"sessionId"`
	CAID          string `json:"caId"`
	NewRandomness string `json:"newRandomness"`
}

func parseNumber(v string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(v, 16)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("invalid positive hexadecimal integer")
	}
	return n, nil
}
func (a *HOAAnchor) numbers() (hoa.Group, *big.Int, *big.Int, *big.Int, error) {
	var v hoa.Group
	var err error
	if v.P, err = parseNumber(a.P); err != nil {
		return v, nil, nil, nil, err
	}
	if v.Q, err = parseNumber(a.Q); err != nil {
		return v, nil, nil, nil, err
	}
	if v.G, err = parseNumber(a.G); err != nil {
		return v, nil, nil, nil, err
	}
	pk, err := parseNumber(a.Public)
	if err != nil {
		return v, nil, nil, nil, err
	}
	h, err := parseNumber(a.Hash)
	if err != nil {
		return v, nil, nil, nil, err
	}
	r, err := parseNumber(a.Randomness)
	return v, pk, h, r, err
}
func (c *Contract) getHOAAnchor(s shim.ChaincodeStubInterface, id string) (*HOAAnchor, error) {
	v := new(HOAAnchor)
	err := read(s, "hoa-anchor", id, v)
	return v, err
}

// RegisterHOAAnchor binds initial HOA hash to a CA's current certificate and path.
// Parameters: CA ID, p, q, g, delegated public key, HOA hash, randomness (all hex).
func (c *Contract) registerHOAAnchor(s shim.ChaincodeStubInterface, args []string) error {
	if e := expect(args, 7); e != nil {
		return e
	}
	ca, e := c.getCA(s, args[0])
	if e != nil {
		return e
	}
	if e = checkOwner(s, ca); e != nil {
		return e
	}
	if ca.ActiveMigration != "" {
		return fmt.Errorf("cannot replace anchor during migration")
	}
	if _, e = c.getHOAAnchor(s, ca.ID); e == nil {
		return fmt.Errorf("HOA anchor already exists")
	}
	anchor := HOAAnchor{CAID: ca.ID, CertificateHash: ca.CertHash, TrustParent: ca.Parent, P: args[1], Q: args[2], G: args[3], Public: args[4], Hash: args[5], Randomness: args[6]}
	v, pk, h, r, e := anchor.numbers()
	if e != nil {
		return e
	}
	cert, e := parseCert(ca.CertPEM)
	if e != nil {
		return e
	}
	if !hoa.Verify(v, pk, cert.Raw, []byte(ca.Parent+"/"+ca.ID), h, r) {
		return fmt.Errorf("invalid initial HOA hash")
	}
	return save(s, "hoa-anchor", ca.ID, anchor)
}
