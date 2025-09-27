package jose

import "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"

type JSONWebSignature = jose.JSONWebSignature

type SignatureVerifier = jose.SignatureVerifier

type SignatureVerifirFunc = jose.SignatureVerifierFunc

type DefaultSigningInputVerifier = jose.DefaultSigningInputVerifier

type JWSParseOpt = jose.JWSParseOpt

type Signer = jose.Signer

func NewJWS(protectedHeaders, unprotectedHeaders Headers, payload []byte, signer Signer) (*JSONWebSignature, error) {
	return jose.NewJWS(protectedHeaders, unprotectedHeaders, payload, signer)
}

func ParseJWS(jws string, verifier SignatureVerifier, opts ...JWSParseOpt) (*JSONWebSignature, error) {
	return jose.ParseJWS(jws, verifier, opts...)
}
