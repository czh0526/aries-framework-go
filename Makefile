.PHONE: all
all: gen-proto

.PHONE: gen-proto
gen-proto:
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto --go_opt=paths=source_relative proto/tink/ecdh_aead.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto --go_opt=paths=source_relative proto/tink/aes_cbc.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto --go_opt=paths=source_relative proto/tink/aes_cbc_hmac_aead.proto
	protoc --proto_path=./proto/tink -I /Users/zhihongcai/Workspaces/github.com/tink-crypto/tink --go_out=./component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto --go_opt=paths=source_relative proto/tink/secp256k1.proto


gen-mock:
	mockgen -destination pkg/internal/gomocks/spi/storage/mocks.gen.go -self_package mocks -package mocks github.com/czh0526/aries-framework-go/spi/storage Provider,Store
	mockgen -destination pkg/internal/gomocks/didcomm/common/service/mocks.gen.go -self_package mocks -package mocks github.com/czh0526/aries-framework-go/pkg/didcomm/common/service Messenger,MessengerHandler
	mockgen -destination pkg/internal/gomocks/didcomm/messenger/mocks.gen.go -self_package mocks -package mocks github.com/czh0526/aries-framework-go/pkg/didcomm/messenger Provider
	mockgen -destination pkg/internal/gomocks/didcomm/dispatcher/mocks.gen.go -self_package mocks -package mocks github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher Outbound


gen-openapi-spec:
	swagger generate spec -w cmd/aries-agent-rest -o build/rest/openapi/spec/openAPI.yml

.PHONE: build
build:
	cd ./pkg/framework/aries
	go build ./...