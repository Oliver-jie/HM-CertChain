package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// CAEdge is a tamper-evident logical cross-reference, NOT a native Fabric block-header field.
type CAEdge struct {
	CAID           string `json:"caId"`
	BlockNumber    uint64 `json:"blockNumber"`
	BlockHash      string `json:"blockHash"`
	PreviousCAHash string `json:"previousCaHash"`
	DataDigest     string `json:"dataDigest"`
}

func NewEdge(ca string, blockNumber uint64, blockHeaderHash []byte, previous *CAEdge, blockData []byte) (CAEdge, error) {
	if ca == "" || len(blockHeaderHash) != 32 {
		return CAEdge{}, errors.New("invalid CA or block hash")
	}
	e := CAEdge{CAID: ca, BlockNumber: blockNumber, BlockHash: hex.EncodeToString(blockHeaderHash)}
	if previous != nil {
		if previous.CAID != ca || previous.BlockNumber >= blockNumber {
			return CAEdge{}, errors.New("invalid previous CA link")
		}
		e.PreviousCAHash = previous.BlockHash
	}
	digest := sha256.Sum256(blockData)
	e.DataDigest = hex.EncodeToString(digest[:])
	return e, nil
}

// VerifyChain verifies the CA-oriented logical link order. Hash authenticity
// MUST be verified against Fabric's ledger BlockHeaderHash separately.
func VerifyChain(edges []CAEdge) error {
	seen := map[string]bool{}
	for i, e := range edges {
		if e.CAID == "" || len(e.BlockHash) != 64 || seen[e.BlockHash] {
			return errors.New("bad or duplicate CA edge")
		}
		seen[e.BlockHash] = true
		if i == 0 {
			if e.PreviousCAHash != "" {
				return errors.New("first edge must be genesis of this CA")
			}
		} else if e.CAID != edges[i-1].CAID || e.BlockNumber <= edges[i-1].BlockNumber || e.PreviousCAHash != edges[i-1].BlockHash {
			return fmt.Errorf("invalid CA edge at %d", i)
		}
	}
	return nil
}

// AuditEvent is an append-only logical modification record, not a physical block rewrite.
type AuditEvent struct {
	SessionID      string `json:"sessionId"`
	CAID           string `json:"caId"`
	OldCertificate string `json:"oldCertificate"`
	NewCertificate string `json:"newCertificate"`
	ProofDigest    string `json:"proofDigest"`
}

func EncodeAudit(v AuditEvent) ([]byte, error) {
	if v.SessionID == "" || v.CAID == "" || v.ProofDigest == "" {
		return nil, errors.New("invalid event")
	}
	return json.Marshal(v)
}
