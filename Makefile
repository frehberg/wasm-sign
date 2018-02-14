
PRIV_FILE=signerkey.pem
PUB_FILE=signerkey.pub.pem

WASM_FILE=res/transform.wasm
SIGNED_WASM_FILE=res/transform-signed.wasm

$(PRIV_FILE):
	openssl ecparam -name secp256k1 -genkey -noout -out $(PRIV_FILE)

$(PUB_FILE): $(PRIV_FILE)
	openssl ec -in $(PRIV_FILE) -pubout -outform pem -out $(PUB_FILE)

all:  $(PRIV_FILE) $(PUB_FILE)

test: $(PRIV_FILE) $(PUB_FILE)
	cargo run -- -k $(PRIV_FILE) $(WASM_FILE) $(SIGNED_WASM_FILE)
	cargo run -- -v -k $(PUB_FILE) $(SIGNED_WASM_FILE)

asn1parse:  
	openssl asn1parse -in $(PRIV_FILE) -inform pem

clean:
	rm -f *.pem

