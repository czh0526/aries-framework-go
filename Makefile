.PHONE: all
all: gen-proto

.PHONE: gen-proto
gen-proto:
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto --go_opt=paths=source_relative proto/tink/ecdh_aead.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto --go_opt=paths=source_relative proto/tink/aes_cbc.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto --go_opt=paths=source_relative proto/tink/aes_cbc_hmac_aead.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto --go_opt=paths=source_relative proto/tink/secp256k1.proto

.PHONE: build
build:
	cd ./pkg/framework/aries
	go build ./...