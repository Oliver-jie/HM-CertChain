package sw

import (
    "errors"
    "math/big"
)

// Setup implements the paper's Setup entry point using externally provisioned
// prime-order group parameters. Keep the master secret off-chain.
func Setup(params *HOAParameters) (*HOAKeyPair, error) { return HOASetup(params) }

// AuthSetup implements a CA-bound additive derivation, x_ca = x_root + H(cid)
// (mod q). It is not the paper's unverified Algorithm 1 exponentiation line.
func AuthSetup(params *HOAParameters, masterSecret *big.Int, caID string) (*HOAKeyPair, error) {
    if params == nil || masterSecret == nil || caID == "" ||
        masterSecret.Sign() <= 0 || masterSecret.Cmp(params.Q) >= 0 {
        return nil, errors.New("invalid master key or CA identifier")
    }
    delta := hoaDigestScalar(params.Q, "HM-CertChain/delegation/v1", []byte(caID))
    key := new(big.Int).Add(masterSecret, delta)
    key.Mod(key, params.Q)
    if key.Sign() == 0 { return nil, errors.New("derived zero scalar") }
    return &HOAKeyPair{Public: new(big.Int).Exp(params.G,key,params.P),Secret:key},nil
}

func Hash(params *HOAParameters, public *big.Int, message, trustPath []byte) (*big.Int,*big.Int,error) {
    return HOAHash(params,public,message,trustPath)
}
func Verify(params *HOAParameters, public *big.Int, message, trustPath []byte, h,r *big.Int) bool {
    return HOAVerify(params,public,message,trustPath,h,r)
}
func Adapt(params *HOAParameters, key *HOAKeyPair,oldMessage,oldPath,newMessage,newPath []byte,h,oldR *big.Int)(*big.Int,error){
    return HOAAdapt(params,key,oldMessage,oldPath,newMessage,newPath,h,oldR)
}

// Trace identifies a CA **only from a registered authorization record**.
// It does not recover CA identity from bare hash collisions and MUST NOT be
// cited as a proof of the paper's cryptographic Trace property.
func Trace(params *HOAParameters, masterPublic *big.Int,caID string,
    caPublic *big.Int,oldMessage,oldPath,newMessage,newPath []byte,h,oldR,newR *big.Int)(string,error) {
    if params == nil || masterPublic == nil || caPublic == nil || caID == "" {
        return "",errors.New("missing authorization record")
    }
    delta := hoaDigestScalar(params.Q,"HM-CertChain/delegation/v1",[]byte(caID))
    computed := new(big.Int).Exp(params.G,delta,params.P)
    computed.Mul(computed,masterPublic).Mod(computed,params.P)
    if computed.Cmp(caPublic)!=0 || !HOATrace(params,caPublic,oldMessage,oldPath,newMessage,newPath,h,oldR,newR){
        return "",errors.New("invalid delegated key or adaptation record")
    }
    return caID,nil
}
