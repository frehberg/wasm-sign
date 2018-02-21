extern crate env_logger;
extern crate getopts;
extern crate openssl;
extern crate base64;
extern crate parity_wasm;

use std::vec::Vec;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;

//use parity_wasm::elements::Error as ParityWasmError;
// use parity_wasm::deserialize_buffer;
use parity_wasm::elements::{
    Module,
    Error as ParityError,
    Section,
    CustomSection,
    Serialize,
    Deserialize,
};

const DEFAULT_SECTION_NAME: &str = "signature";
const CUSTOM_SECTION_HEAD_SIZE: usize = 12;
const CUSTOM_SECTION_PAYLOAD_START: usize = CUSTOM_SECTION_HEAD_SIZE;

const PAYLOAD_VER_IDX: usize = 0;
const PAYLOAD_LEN_IDX: usize = 1;
const PAYLOAD_ECDSA_IDX: usize = 2;
const ECDSA_SIGNATURE_SIZE_MAX: usize = 104; // secp256k1 72 bytes, secp384r1 104 bytes
const CUSTOM_SECTION_SIZE: usize = CUSTOM_SECTION_HEAD_SIZE + 2 + ECDSA_SIGNATURE_SIZE_MAX; // 118
const VERSION: u8 = 0;
const PAD: u8 = 0;


#[derive(Debug)]
pub enum Error { NoSignature, BadVersion, BadCipher, MalformedKey, MalformedModule, HasSignature, InternalError }

/// Configuration structure
pub struct Config {
    name: String,
}


/// parse EC private key from byte-sequence in PEM format
#[allow(dead_code)]
fn to_private_key(pemkey: &[u8]) -> Result<PKey<openssl::pkey::Private>, ErrorStack>
{
    let eckey = EcKey::private_key_from_pem(pemkey)?;
    let pkey = PKey::from_ec_key(eckey);
    return pkey;
}

/// parse EC public key from byte-sequence in PEM format
#[allow(dead_code)]
fn to_public_key(pemkey: &[u8]) -> Result<PKey<openssl::pkey::Public>, ErrorStack>
{
    let pkey = PKey::public_key_from_pem(&pemkey);
    return pkey;
}

#[allow(dead_code)]
fn to_module(mut bytecode: &[u8]) -> Result<Module, ParityError>
{
    Module::deserialize(&mut bytecode)
}

fn create_signer<'a>(pkey: &'a PKey<openssl::pkey::Private> ) -> Result<Signer<'a>, Error>
{
    match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(signer) => match signer.len() {
            Ok(len) if len <= ECDSA_SIGNATURE_SIZE_MAX => Result::Ok(signer),
            Ok(len) if len > ECDSA_SIGNATURE_SIZE_MAX => Result::Err(Error::BadCipher),
            _ => Result::Err(Error::BadCipher),
        },
        _ => Result::Err(Error::BadCipher),
    }
}

fn create_verifier<'a>(pkey: &'a PKey<openssl::pkey::Public>) -> Result<Verifier<'a>, Error>
{
    match Verifier::new(MessageDigest::sha256(), &pkey) {
        Ok(verifier) => Result::Ok(verifier),
        _ => Result::Err(Error::BadCipher),
    }
}

/// create the signature
fn sign<'a>(signer: &mut Signer<'a>, bytecode: &[u8]) -> Result<Vec<u8>, Error>
{
    match signer.update(bytecode.as_ref()) {
        Ok(_) => (),
        Err(_) => return Result::Err(Error::InternalError),
    };

    match signer.sign_to_vec() {
        Ok(vec) => Ok(vec),
        Err(_) => Err(Error::InternalError)
    }
}

/// verify the signature
fn verify<'a>(verifier: &mut Verifier<'a>, bytecode: &[u8], signature: &[u8]) -> Result<bool, Error>
{
    match verifier.update(bytecode.as_ref()) {
        Ok(_) => (),
        Err(_) => return Result::Err(Error::InternalError),
    };

    match verifier.verify(&signature) {
        Ok(verdict) => Ok(verdict),
        Err(_) => Err(Error::InternalError),
    }
}


impl Config {
    pub fn new() -> Config {
        Config {
            name: DEFAULT_SECTION_NAME.to_owned(),
        }
    }

    /// Signing the bytecode using the private key
    pub fn sign<'a>(&self, pkey: &'a PKey<openssl::pkey::Private>, bytecode: &[u8]) -> Result<Vec<u8>, Error>
    {
        let mut result = bytecode.to_owned();

        let mut signer = create_signer(&pkey)?;

        let mut signature = sign(&mut signer, bytecode.as_ref())?;

        let required_padding = ECDSA_SIGNATURE_SIZE_MAX - signature.len();

        let mut custom: CustomSection = Default::default();

        // In CustomSection set the name, append the signature with padding
        // append to end of module bytecode
        custom.name_mut().push_str(self.name.as_ref());

        custom.payload_mut().push(VERSION);
        assert!(signature.len() < 256);
        custom.payload_mut().push(signature.len() as u8);
        custom.payload_mut().append(&mut signature);

        // add trailing padding
        for _i in 0..required_padding {
            custom.payload_mut().push(PAD);
        }

        let section = Section::Custom(custom);

        let mut section_bytecode = Vec::with_capacity(CUSTOM_SECTION_SIZE);

        if section.serialize(&mut section_bytecode).is_err() {
            return Result::Err(Error::InternalError);
        }

        result.append(section_bytecode.as_mut());

        return Result::Ok(result);
    }

    /// Verifying the signature at the end of the bytecode using the public key
    pub fn verify<'a>(&self, pkey: &'a PKey<openssl::pkey::Public>, signed_bytecode: &[u8]) -> Result<bool, Error>
    {
        let mut verifier = create_verifier(&pkey)?;

        if signed_bytecode.len() <= CUSTOM_SECTION_SIZE {
            return Result::Err(Error::MalformedModule);
        }

        let (bytecode, custom_section_bytecode) =
            signed_bytecode.split_at(signed_bytecode.len() - CUSTOM_SECTION_SIZE);

        let custom_section_payload =
            &custom_section_bytecode[CUSTOM_SECTION_PAYLOAD_START..];

        let ver: &u8 = &custom_section_payload[PAYLOAD_VER_IDX];
        let len = custom_section_payload[PAYLOAD_LEN_IDX] as usize;

        let ecdsa_data =
            &custom_section_payload[PAYLOAD_ECDSA_IDX..(len + PAYLOAD_ECDSA_IDX)];

        if *ver != VERSION || len > ECDSA_SIGNATURE_SIZE_MAX {
            return Result::Err(Error::NoSignature);
        }

        verify(&mut verifier, bytecode, ecdsa_data)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use base64::decode;


    const PRIVATE_KEY_SECP256K1: &[u8] = b"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILz/A1lrSfoGyINIiy0Ip7OTNHCbpH5W89235ulbVneOoAcGBSuBBAAK
oUQDQgAEEglOsMyoScjUMuUomECq1U6gaPUEfOmvOYBjxBEdd8fN5ZfFHYeQwNAs
+kK96P1/ODkqQTTKv18kDanmsavXYw==
-----END EC PRIVATE KEY-----
";

    const PUBLIC_KEY_SECP256K1: &[u8] = b"-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEglOsMyoScjUMuUomECq1U6gaPUEfOmv
OYBjxBEdd8fN5ZfFHYeQwNAs+kK96P1/ODkqQTTKv18kDanmsavXYw==
-----END PUBLIC KEY-----";


    const PRIVATE_KEY_SECP384R1: &[u8] = b"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDp7Z74viFQDPzWuk4tt5SahPbyCm6WQbU9HdMg4jK9OfzAd/YpBDju
Xu7YstRrJYSgBwYFK4EEACKhZANiAARDf5u2T0SdjCsOsNbxBCidgozBeWHZ3luE
aIFsOGDGOgiDynKaTAUhf7oOvMhJi0r32ocfATgPyPso7fvLvjJKJ7PaHRxErqZg
wAqxaRDUW47eolEjWjhgvljw8K2Ib4s=
-----END EC PRIVATE KEY-----
";

    const PUBLIC_KEY_SECP384R1: &[u8] = b"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQ3+btk9EnYwrDrDW8QQonYKMwXlh2d5b
hGiBbDhgxjoIg8pymkwFIX+6DrzISYtK99qHHwE4D8j7KO37y74ySiez2h0cRK6m
YMAKsWkQ1FuO3qJRI1o4YL5Y8PCtiG+L
-----END PUBLIC KEY-----
";


    const WASM_BASE64: &str =
        "AGFzbQEAAAAADAZkeWxpbmuAgMACAAGKgICAAAJgAn9/AX9gAAACwYCAgAAEA2VudgptZW1vcnlCYXNl\
            A38AA2VudgZtZW1vcnkCAIACA2VudgV0YWJsZQFwAAADZW52CXRhYmxlQmFzZQN/AAOEgICAAAMAAQEGi\
            4CAgAACfwFBAAt/AUEACwejgICAAAIKX3RyYW5zZm9ybQAAEl9fcG9zdF9pbnN0YW50aWF0ZQACCYGAgI\
            AAAArpgICAAAPBgICAAAECfwJ/IABBAEoEQEEAIQIFIAAPCwNAIAEgAmoiAywAAEHpAEYEQCADQfkAOgA\
            ACyACQQFqIgIgAEcNAAsgAAsLg4CAgAAAAQuVgICAAAACQCMAJAIjAkGAgMACaiQDEAELCw==";

    #[test]
    fn test_to_private_key_secp256k1() {
        assert!(PRIVATE_KEY_SECP256K1.len() > 0);
        assert!(to_private_key(PRIVATE_KEY_SECP256K1).is_ok());
    }

    #[test]
    fn test_to_public_key_secp256k1() {
        assert!(PUBLIC_KEY_SECP256K1.len() > 0);
        assert!(to_public_key(PUBLIC_KEY_SECP256K1).is_ok());
    }

    #[test]
    fn test_to_private_key_secp384r1() {
        assert!(PRIVATE_KEY_SECP384R1.len() > 0);
        assert!(to_private_key(PRIVATE_KEY_SECP384R1).is_ok());

        let pkey = to_private_key(PRIVATE_KEY_SECP384R1).unwrap();
        let signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
        println!("secp384r1-len={}", signer.len().unwrap());

    }

    #[test]
    fn test_to_public_key_secp384r1() {
        assert!(PUBLIC_KEY_SECP384R1.len() > 0);
        assert!(to_public_key(PUBLIC_KEY_SECP384R1).is_ok());

    }

    #[test]
    fn test_wasm_parse() {
        assert!(WASM_BASE64.len() > 0);

        let mut bytecode = decode(WASM_BASE64).unwrap();
        assert!(bytecode.len() > 0);

        let module_result = to_module(bytecode.as_mut());
        assert!(module_result.is_ok());
    }

    #[test]
    fn test_basic_sign_verify() {
        assert!(WASM_BASE64.len() > 0);

        let mut bytecode = decode(WASM_BASE64).unwrap();
        assert!(bytecode.len() > 0);

        let module_result = to_module(bytecode.as_mut());
        assert!(module_result.is_ok());

        let privkey = to_private_key(PRIVATE_KEY_SECP256K1).unwrap();

        let pubkey = to_public_key(PUBLIC_KEY_SECP256K1).unwrap();

        let mut signer = create_signer(&privkey).unwrap();
        let mut verifier = create_verifier(&pubkey).unwrap();

        let signature =
            sign(&mut signer, bytecode.as_ref());

        assert!(signature.is_ok());

        assert!(verify(&mut verifier,
                       bytecode.as_ref(),
                       signature.unwrap().as_ref())
            .unwrap());
    }

    #[test]
    fn test_wasm_sign_verify() {
        assert!(WASM_BASE64.len() > 0);

        let mut bytecode = decode(WASM_BASE64).unwrap();
        assert!(bytecode.len() > 0);

        let module_result = to_module(bytecode.as_mut());
        assert!(module_result.is_ok());

        let privkey = to_private_key(PRIVATE_KEY_SECP256K1).unwrap();

        let pubkey = to_public_key(PUBLIC_KEY_SECP256K1).unwrap();

        let config = Config::new();

        let signed_bytecode =
            config.sign(&privkey, bytecode.as_ref()).unwrap();

        assert!(to_module(signed_bytecode.as_ref()).is_ok());

        assert_eq!(
            to_module(bytecode.as_ref()).unwrap().sections().len() + 1,
            to_module(signed_bytecode.as_ref()).unwrap().sections().len());

        config.verify(&pubkey, signed_bytecode.as_ref()).unwrap();
    }
}