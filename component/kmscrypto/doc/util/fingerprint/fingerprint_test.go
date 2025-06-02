package fingerprint

import (
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestMulticodec(t *testing.T) {
	var code uint64
	for code = 0; code < 100000; code += 100 {
		codec := multicodec(code)
		fmt.Printf("%d => %x\n", code, codec)
	}
}

const (
	edPubKeyBase58     = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
	edExpectedDIDKey   = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	edExpectedDIDKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll

	ecP256PubKeyBase58     = "3YRwdf868zp2t8c4oT4XdYfCihMsfR1zrVYyXS5SS4FwQ7wftDfoY5nohvhdgSk9LxyfzjTLzffJPmHgFBqizX9v"
	ecP256ExpectedDIDKey   = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z"                                                                                             //nolint:lll
	ecP256ExpectedDIDKeyID = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z#zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z" //nolint:lll

	ecP384PubKeyBase58     = "tAjHMcvoBXs3BSihDV85trHmstc3V3vTP7o2Si72eCWdVzeGgGvRd8h5neHEbqSL989h53yNj7M7wHckB2bKpGKQjnPDD7NphDa9nUUBggCB6aCWterfdXbH5DfWPZx5oXU"                                                                                                                                                     //nolint:lll
	ecP384ExpectedDIDKey   = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU"                                                                                                                                         //nolint:lll
	ecP384ExpectedDIDKeyID = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU#zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU" //nolint:lll

	ecP521PubKeyBase58     = "mTQ9pPr2wkKdiTHhVG7xmLwyJ5mrgq1FKcHFz2XJprs4zAPtjXWFiEz6vsscbseSEzGdjAVzcUhwdodT5cbrRjQqFdz8d1yYVqMHXsVCdCUrmWNNHcZLJeYCn1dCtQX9YRVdDFfnzczKFxDXe9HusLqBWTobbxVvdj9cTi7rSWVznP5Emfo"                                                                                                                                                                                                       //nolint:lll
	ecP521ExpectedDIDKey   = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK"                                                                                                                                                                                          //nolint:lll
	ecP521ExpectedDIDKeyID = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK#zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK" //nolint:lll

)

func TestCreateDIDKeyByCode(t *testing.T) {

	t.Run("test create Ed25519 DID", func(t *testing.T) {
		keyBytes := base58.Decode(edPubKeyBase58)

		didKey, keyID := CreateDIDKeyByCode(ED25519PubKeyMultiCodec, keyBytes)
		require.Equal(t, edExpectedDIDKey, didKey)
		require.Equal(t, edExpectedDIDKeyID, keyID)
	})

	t.Run("test create P-256 DID", func(t *testing.T) {
		keyBytes := base58.Decode(ecP256PubKeyBase58)

		didKey, keyID := CreateDIDKeyByCode(P256PubKeyMultiCodec, keyBytes)
		require.Equal(t, ecP256ExpectedDIDKey, didKey)
		require.Equal(t, ecP256ExpectedDIDKeyID, keyID)
	})

	t.Run("test create P-384 DID", func(t *testing.T) {
		keyBytes := base58.Decode(ecP384PubKeyBase58)

		didKey, keyID := CreateDIDKeyByCode(P384PubKeyMultiCodec, keyBytes)
		require.Equal(t, ecP384ExpectedDIDKey, didKey)
		require.Equal(t, ecP384ExpectedDIDKeyID, keyID)
	})

	t.Run("test create P-521 DID", func(t *testing.T) {
		keyBytes := base58.Decode(ecP521PubKeyBase58)

		didKey, keyID := CreateDIDKeyByCode(P521PubKeyMultiCodec, keyBytes)
		require.Equal(t, ecP521ExpectedDIDKey, didKey)
		require.Equal(t, ecP521ExpectedDIDKeyID, keyID)
	})
}

func TestPubKeyFromFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("test create Ed25519 DID from Fingerprint", func(t *testing.T) {
		pubKey, code, err := PubKeyFromFingerprint(strings.Split(edExpectedDIDKeyID, "#")[1])
		require.NoError(t, err)
		require.Equal(t, ED25519PubKeyMultiCodec, int(code))
		require.Equal(t, edPubKeyBase58, base58.Encode(pubKey))
	})

	t.Run("test create P-256 DID from Fingerprint", func(t *testing.T) {
		pubKey, code, err := PubKeyFromFingerprint(strings.Split(ecP256ExpectedDIDKeyID, "#")[1])
		require.NoError(t, err)
		require.Equal(t, P256PubKeyMultiCodec, int(code))
		require.Equal(t, ecP256PubKeyBase58, base58.Encode(pubKey))
	})

	t.Run("test create P-384 DID from Fingerprint", func(t *testing.T) {
		pubKey, code, err := PubKeyFromFingerprint(strings.Split(ecP384ExpectedDIDKeyID, "#")[1])
		require.NoError(t, err)
		require.Equal(t, P384PubKeyMultiCodec, int(code))
		require.Equal(t, ecP384PubKeyBase58, base58.Encode(pubKey))
	})

	t.Run("test create P-384 DID from Fingerprint", func(t *testing.T) {
		pubKey, code, err := PubKeyFromFingerprint(strings.Split(ecP521ExpectedDIDKeyID, "#")[1])
		require.NoError(t, err)
		require.Equal(t, P521PubKeyMultiCodec, int(code))
		require.Equal(t, ecP521PubKeyBase58, base58.Encode(pubKey))
	})
}
