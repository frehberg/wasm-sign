
PRIV_FILE=signerkey.pem
PUB_FILE=signerkey.pub.pem

PRIV_384_FILE=signerkey384.pem
PUB_384_FILE=signerkey384.pub.pem

WASM_FILE=res/transform.wasm
SIGNED_WASM_FILE=res/transform-signed.wasm

$(PRIV_FILE):
	openssl ecparam -name secp256k1 -genkey -noout -out $(PRIV_FILE)

$(PRIV_384_FILE):
	openssl ecparam -name secp384r1 -genkey -noout -out $(PRIV_384_FILE)

$(PUB_FILE): $(PRIV_FILE)
	openssl ec -in $(PRIV_FILE) -pubout -outform pem -out $(PUB_FILE)

$(PUB_384_FILE): $(PRIV_384_FILE)
	openssl ec -in $(PRIV_384_FILE) -pubout -outform pem -out $(PUB_384_FILE)

all:  $(PRIV_FILE) $(PRIV_384_FILE) $(PUB_FILE) $(PUB_384_FILE) 

test: $(PRIV_FILE) $(PUB_FILE)
	cargo run -- -k $(PRIV_FILE) $(WASM_FILE) $(SIGNED_WASM_FILE)
	cargo run -- -v -k $(PUB_FILE) $(SIGNED_WASM_FILE)

asn1parse:  
	openssl asn1parse -in $(PRIV_FILE) -inform pem
	openssl asn1parse -in $(PRIV_384_FILE) -inform pem

print-curves:
	openssl ecparam -list_curves
clean:
	rm -f *.pem


