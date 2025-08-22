package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"github.com/stretchr/testify/require"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	tinkaeadsubtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	hybridsubtle "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"math/big"
	"testing"
)

const testMessage = "test message"

func TestCrypto_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name         string
		ivSize       int
		aeadTemplate *tinkpb.KeyTemplate
	}{
		{
			name:         "test AES256GCM encryption",
			ivSize:       tinkaeadsubtle.AESGCMIVSize,
			aeadTemplate: tinkaead.AES256GCMKeyTemplate(),
		},
		{
			name:         "test AES128CBCHMACSHA256 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES128CBCHMACSHA256KeyTemplate(),
		},
		{
			name:         "test AES192CBCHMACSHA384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES192CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA5384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA512 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA512KeyTemplate(),
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.aeadTemplate)
			require.NoError(t, err)
			km := keyset.NewManagerFromHandle(kh)

			c := Crypto{}
			msg := []byte(testMessage)
			aad := []byte("some additional data")
			cipherText, err := c.Encrypt(msg, aad, kh)
			require.NoError(t, err)
			require.NotEmpty(t, cipherText)

			// 新增加一个 Key
			keyId2, err := km.Add(tc.aeadTemplate)
			require.NoError(t, err)
			require.NotEmpty(t, keyId2)
			// 再新增一个 Key
			keyId3, err := km.Add(tc.aeadTemplate)
			require.NoError(t, err)
			require.NotEmpty(t, keyId3)
			// 设置 PrimaryKey
			err = km.SetPrimary(keyId3)
			require.NoError(t, err)
			kh, err = km.Handle()
			require.NoError(t, err)

			plainText, err := c.Decrypt(cipherText, aad, kh)
			require.NoError(t, err)
			require.Equal(t, msg, plainText)

			plainText, err = c.Decrypt([]byte("bad cipher"), aad, kh)
			require.Error(t, err)
			require.Empty(t, plainText)
		})
	}
}

func TestCrypto_SignVerify(t *testing.T) {
	t.Run("test with Ed25519 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-256 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-384 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP384SHA512KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with secp256k1 signature", func(t *testing.T) {
		derTemplate, err := secp256k1.DERKeyTemplate()
		require.NoError(t, err)

		kh, err := keyset.NewHandle(derTemplate)
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})
}

func TestCrypto_ComputeVerifyMAC(t *testing.T) {
	t.Run("test with compute MAC", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		msg := []byte(testMessage)
		macBytes, err := c.ComputeMAC(msg, kh)
		require.NoError(t, err)
		require.NotEmpty(t, macBytes)

		err = c.VerifyMAC(macBytes, msg, kh)
		require.NoError(t, err)
	})
}

func TestCrypto_ECDHES_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	// 随机生成 Content Encryption Key
	cek := random.GetRandomBytes(uint32(crypto.DefKeySize))
	// 随机生成 apu, apv
	apu := random.GetRandomBytes(uint32(10))
	apv := random.GetRandomBytes(uint32(10))

	// 不提供 recPubKey，报错
	_, err = c.WrapKey(cek, apu, apv, nil)
	require.EqualError(t, err, "wrapKey: recipient public key is required")

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	// 测试 Wrap Key
	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey)
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.Equal(t, wrappedKey.APU, apu)
	require.Equal(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDHESA256KWAlg)

	// 测试 Unwrap Key
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle)
	require.NoError(t, err)
	require.Equal(t, cek, uCEK)
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientPubKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	// 随机生成加密密钥
	cek := random.GetRandomBytes(uint32(crypto.DefKeySize * 2))
	apu := random.GetRandomBytes(uint32(10))
	apv := random.GetRandomBytes(uint32(10))

	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientPubKey, spicrypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.Equal(t, wrappedKey.APU, apu)
	require.Equal(t, wrappedKey.APV, apv)

	senderPubKey, err := senderKH.Public()
	require.NoError(t, err)

	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, spicrypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.Equal(t, cek, uCEK)
}

func TestCrypto_ECDHES_Wrap_Unwrap_ForAllKeyTypes(t *testing.T) {
	tests := []struct {
		tcName   string
		keyTempl *tinkpb.KeyTemplate
		kwAlg    string
		keyType  string
		keyCurve string
		useXC20P bool
		senderKT *tinkpb.KeyTemplate
		err      string
	}{
		{
			tcName:   "key wrap using ECDH-ES with NISI P-256 key and A256GCM kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST p-384 key and A256GCM kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST p-521 key and A256GCM kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
		},
		{
			tcName:   "key wrap using ECDH-ES with X25519 key and A256GCM kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDHESA256KWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
		},
		// ------------------------------------------------------------------------------
		{
			tcName:   "key wrap using ECDH-ES with NIST P-256 key and XC20P kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-384 key and XC20P kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with NIST P-521 key and XC20P kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-ES with X25519 key and XC20P kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDHESXC20PKWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			useXC20P: true,
		},
		// -------------------------------------------------------------------------
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-256 key and A256GCM kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			senderKT: ecdh.NISTP256ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU With NIST p-384 key and A256GCM kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			senderKT: ecdh.NISTP384ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU With NIST p-521 key and A256GCM kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			senderKT: ecdh.NISTP521ECDHKWKeyTemplate(),
		},
		{
			tcName:   "key wrap using ECDH-1PU With X25519 key and A256GCM kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUA256KWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			senderKT: ecdh.X25519ECDHKWKeyTemplate(),
		},
		// --------------------------------------------------------------------------------
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-256 key and XC20P kw",
			keyTempl: ecdh.NISTP256ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P256().Params().Name,
			senderKT: ecdh.NISTP256ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-384 key and XC20P kw",
			keyTempl: ecdh.NISTP384ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P384().Params().Name,
			senderKT: ecdh.NISTP384ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with NIST P-521 key and XC20P kw",
			keyTempl: ecdh.NISTP521ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_EC.String(),
			keyCurve: elliptic.P521().Params().Name,
			senderKT: ecdh.NISTP521ECDHKWKeyTemplate(),
			useXC20P: true,
		},
		{
			tcName:   "key wrap using ECDH-1PU with X25519 key and XC20P kw",
			keyTempl: ecdh.X25519ECDHKWKeyTemplate(),
			kwAlg:    ECDH1PUXC20PKWAlg,
			keyType:  ecdhpb.KeyType_OKP.String(),
			keyCurve: "X25519",
			senderKT: ecdh.X25519ECDHKWKeyTemplate(),
			useXC20P: true,
		},
	}

	c, err := New()
	require.NoError(t, err)

	apu := random.GetRandomBytes(uint32(10))
	apv := random.GetRandomBytes(uint32(10))

	for _, tt := range tests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			keySize := aesCEKSize1PU(tc.kwAlg)

			cek := random.GetRandomBytes(uint32(keySize))
			recipientKeyHandle, err := keyset.NewHandle(tc.keyTempl)
			require.NoError(t, err)

			recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
			require.NoError(t, err)

			var senderKH *keyset.Handle

			var wrapKeyOpts []spicrypto.WrapKeyOpts
			if tc.useXC20P {
				wrapKeyOpts = append(wrapKeyOpts, spicrypto.WithXC20PKW())
			}

			if tc.senderKT != nil {
				senderKH, err = keyset.NewHandle(tc.senderKT)
				require.NoError(t, err)

				wrapKeyOpts = append(wrapKeyOpts, spicrypto.WithSender(senderKH))
			}

			wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, wrapKeyOpts...)
			require.NoError(t, err)
			require.NotEmpty(t, wrappedKey.EncryptedCEK)
			require.NotEmpty(t, wrappedKey.EPK)
			require.Equal(t, wrappedKey.APU, apu)
			require.Equal(t, wrappedKey.APV, apv)
			require.Equal(t, tc.kwAlg, wrappedKey.Alg)
			require.Equal(t, tc.keyCurve, wrappedKey.EPK.Curve)
			require.Equal(t, tc.keyType, wrappedKey.EPK.Type)

			if senderKH != nil {
				senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
				require.NoError(t, err)

				wrapKeyOpts = []spicrypto.WrapKeyOpts{spicrypto.WithSender(senderPubKey)}
			}

			uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, wrapKeyOpts...)
			require.NoError(t, err)
			require.Equal(t, cek, uCEK)
		})
	}
}

func TestCrypto_ECDH1PU_Wrap_Unwrap_Key_Using_CryptoPubKey_as_SenderKey(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	c, err := New()
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(crypto.DefKeySize * 2))
	apu := random.GetRandomBytes(uint32(10))
	apv := random.GetRandomBytes(uint32(10))

	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	wrappedKey, err := c.WrapKey(cek, apu, apv, recipientKey, spicrypto.WithSender(senderKH))
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey.EncryptedCEK)
	require.NotEmpty(t, wrappedKey.EPK)
	require.Equal(t, wrappedKey.APU, apu)
	require.Equal(t, wrappedKey.APV, apv)
	require.Equal(t, wrappedKey.Alg, ECDH1PUA256KWAlg)

	// 使用 spicrypto.PublicKey 解密
	uCEK, err := c.UnwrapKey(wrappedKey, recipientKeyHandle, spicrypto.WithSender(senderPubKey))
	require.NoError(t, err)
	require.Equal(t, cek, uCEK)

	crv, err := hybridsubtle.GetCurve(senderPubKey.Curve)
	require.NoError(t, err)

	// 使用 ecdsa.PublicKey 解密
	senderECPubKey := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(senderPubKey.X),
		Y:     new(big.Int).SetBytes(senderPubKey.Y),
	}

	uCEK, err = c.UnwrapKey(wrappedKey, recipientKeyHandle, spicrypto.WithSender(senderECPubKey))
	require.NoError(t, err)
	require.Equal(t, cek, uCEK)
}
