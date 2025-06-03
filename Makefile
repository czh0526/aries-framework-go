.PHONE: all
all: gen-proto

.PHONE: gen-proto
gen-proto:
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto --go_opt=paths=source_relative proto/tink/ecdh_aead.proto

.PHONE: build
build:
	cd ./pkg/framework/aries
	go build ./...