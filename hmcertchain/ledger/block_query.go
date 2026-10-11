package ledger

import (
	"bytes"
	"errors"
	"fmt"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/protoutil"
)

// BlockReader is satisfied by Fabric's blkstorage.BlockStore. It is deliberately
// read-only: a block file must never be rewritten outside the consensus protocol.
type BlockReader interface {
	GetBlockchainInfo() (*cb.BlockchainInfo, error)
	RetrieveBlockByNumber(uint64) (*cb.Block, error)
}

// CAClassifier extracts an authenticated CA identifier from a committed block.
// Its implementation MUST verify the transaction's issuer/signature and the
// application's CA mapping; no CA is inferred from an unauthenticated payload.
type CAClassifier func(*cb.Block) (string, error)

// BlockLink describes a verified, read-only CA-associated logical edge.
// It is not an extension of the native Fabric BlockHeader.
type BlockLink struct {
	CAID           string `json:"caId"`
	Number         uint64 `json:"number"`
	Hash           []byte `json:"hash"`
	PreviousCAHash []byte `json:"previousCaHash,omitempty"`
}

// QueryCA blocks validates native Fabric continuity and data integrity before
// constructing the logical CA-specific backward link chain. The caller-supplied
// classifier must be authenticated. This function does not mutate ledger state.
func QueryCA(reader BlockReader, caID string, classify CAClassifier) ([]BlockLink, error) {
	if reader == nil || classify == nil || caID == "" {
		return nil, errors.New("missing reader, classifier, or CA identifier")
	}
	info, err := reader.GetBlockchainInfo()
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, errors.New("nil blockchain information")
	}
	var links []BlockLink
	var previousBlockHash, previousCAHash []byte
	for n := uint64(0); n < info.Height; n++ {
		block, err := reader.RetrieveBlockByNumber(n)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", n, err)
		}
		if block == nil || block.Header == nil || block.Data == nil || block.Header.Number != n {
			return nil, fmt.Errorf("malformed block %d", n)
		}
		if !bytes.Equal(protoutil.BlockDataHash(block.Data), block.Header.DataHash) {
			return nil, fmt.Errorf("invalid data hash at block %d", n)
		}
		if n > 0 && !bytes.Equal(block.Header.PreviousHash, previousBlockHash) {
			return nil, fmt.Errorf("broken previous hash at block %d", n)
		}
		hash := protoutil.BlockHeaderHash(block.Header)
		previousBlockHash = hash
		issuer, err := classify(block)
		if err != nil {
			return nil, fmt.Errorf("CA classifier at block %d: %w", n, err)
		}
		if issuer == caID {
			links = append(links, BlockLink{CAID: caID, Number: n, Hash: append([]byte(nil), hash...), PreviousCAHash: append([]byte(nil), previousCAHash...)})
			previousCAHash = hash
		}
	}
	return links, nil
}

// VerifyCALinks verifies a returned logical path without relaxing native block
// verification; callers must also authenticate each hash against committed blocks.
func VerifyCALinks(caID string, links []BlockLink) error {
	var previous []byte
	for i, e := range links {
		if e.CAID != caID || len(e.Hash) != 32 || (i > 0 && e.Number <= links[i-1].Number) || !bytes.Equal(e.PreviousCAHash, previous) {
			return fmt.Errorf("invalid CA link at position %d", i)
		}
		previous = e.Hash
	}
	return nil
}
