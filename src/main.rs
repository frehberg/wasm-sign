extern crate env_logger;
extern crate getopts;
extern crate openssl;
extern crate base64;
extern crate parity_wasm;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::vec::Vec;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use getopts::Options;
//use parity_wasm::elements::Error as ParityWasmError;
// use parity_wasm::deserialize_buffer;
use parity_wasm::elements::{
    Module,
    Error,
    Section,
    CustomSection,
    Serialize,
    Deserialize,
};

const DEFAULT_SECTION_NAME: &str = "signature";
const CUSTOM_SECTION_SIZE: usize = 86;
const ECDSA_SIGNATURE_SIZE: usize = 72;
const VERSION: u8 = 0;
const PAD: u8 = 0;

const CUSTOM_SECTION_HEAD_SIZE: usize = 12;
const CUSTOM_SECTION_PAYLOAD_START: usize = CUSTOM_SECTION_HEAD_SIZE;

const PAYLOAD_VER_IDX: usize = 0;
const PAYLOAD_LEN_IDX: usize = 1;
const PAYLOAD_ECDSA_IDX: usize = 2;

#[derive(Debug)]
pub enum WasmError { NoSignature, BadVersion, BadCipher, MalformedKey, MalformedModule, HasSignature, InternalError }

pub struct Config {
    name: String,
}

fn to_module(mut bytecode: &[u8]) -> Result<Module, Error>
{
    Module::deserialize(&mut bytecode)
}

fn create_signer<'a>(pkey: &'a PKey<openssl::pkey::Private>) -> Result<Signer<'a>, WasmError>
{
    match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(signer) => match signer.len() {
            Ok(len) if len == ECDSA_SIGNATURE_SIZE => Result::Ok(signer),
            Ok(len) if len != ECDSA_SIGNATURE_SIZE => Result::Err(WasmError::BadCipher),
            _ => Result::Err(WasmError::BadCipher),
        },
        _ => Result::Err(WasmError::BadCipher),
    }
}

fn create_verifier<'a>(pkey: &'a PKey<openssl::pkey::Public>) -> Result<Verifier<'a>, WasmError>
{
    match Verifier::new(MessageDigest::sha256(), &pkey) {
        Ok(verifier) => Result::Ok(verifier),
        _ => Result::Err(WasmError::BadCipher),
    }
}

/// create the signature
fn sign<'a>(signer: &mut Signer<'a>, bytecode: &[u8]) -> Result<Vec<u8>, WasmError>
{
    match signer.update(bytecode.as_ref()) {
        Ok(_) => (),
        Err(_) => return Result::Err(WasmError::InternalError),
    };

    match signer.sign_to_vec() {
        Ok(vec) => Ok(vec),
        Err(_) => Err(WasmError::InternalError)
    }
}

/// verify the signature
fn verify<'a>(verifier: &mut Verifier<'a>, bytecode: &[u8], signature: &[u8]) -> Result<bool, WasmError>
{
    match verifier.update(bytecode.as_ref()) {
        Ok(_) => (),
        Err(_) => return Result::Err(WasmError::InternalError),
    };

    match verifier.verify(&signature) {
        Ok(verdict) => Ok(verdict),
        Err(_) => Err(WasmError::InternalError),
    }
}

impl Config {
    pub fn new() -> Config {
        Config {
            name: DEFAULT_SECTION_NAME.to_owned(),
        }
    }

    pub fn sign<'a>(&self, pkey: &'a PKey<openssl::pkey::Private>, bytecode: &[u8]) -> Result<Vec<u8>, WasmError>
    {
        let mut result = bytecode.to_owned();

        let mut signer = create_signer(&pkey)?;

        let mut signature = sign(&mut signer, bytecode.as_ref())?;

        let required_padding = signer.len().unwrap() - signature.len();

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
            return Result::Err(WasmError::InternalError);
        }

        result.append(section_bytecode.as_mut());

        return Result::Ok(result);
    }

    pub fn verify<'a>(&self, pkey: &'a PKey<openssl::pkey::Public>, signed_bytecode: &[u8]) -> Result<bool, WasmError>
    {
        let mut verifier = create_verifier(&pkey)?;

        if signed_bytecode.len() <= CUSTOM_SECTION_SIZE {
            return Result::Err(WasmError::MalformedModule);
        }

        let (bytecode, custom_section_bytecode) =
            signed_bytecode.split_at(signed_bytecode.len() - CUSTOM_SECTION_SIZE);

        let custom_section_payload =
            &custom_section_bytecode[CUSTOM_SECTION_PAYLOAD_START..];

        let ver: &u8 = &custom_section_payload[PAYLOAD_VER_IDX];
        let len = custom_section_payload[PAYLOAD_LEN_IDX] as usize;

        let ecdsa_data =
            &custom_section_payload[PAYLOAD_ECDSA_IDX..(len + PAYLOAD_ECDSA_IDX)];

        if *ver != VERSION || len > ECDSA_SIGNATURE_SIZE {
            return Result::Err(WasmError::NoSignature);
        }

        verify(&mut verifier, bytecode, ecdsa_data)
    }
}

/// parse EC private key from byte-sequence in PEM format
fn to_private_key(pemkey: &[u8]) -> Result<PKey<openssl::pkey::Private>, ErrorStack>
{
    let eckey = EcKey::private_key_from_pem(pemkey)?;
    let pkey = PKey::from_ec_key(eckey);
    return pkey;
}

/// parse EC public key from byte-sequence in PEM format
fn to_public_key(pemkey: &[u8]) -> Result<PKey<openssl::pkey::Public>, ErrorStack>
{
    let pkey = PKey::public_key_from_pem(&pemkey);
    return pkey;
}


fn main() {
    env_logger::init();

    let mut opts = Options::new();
    opts.optflag("v", "verify", "verify the signature of a wasm file");
    opts.reqopt("k", "key", "key file", "KEY");
    opts.optflag("d", "der", "key is DER form");
    opts.optflag("p", "pem", "key is PEM form [default]");
    opts.optopt("o", "out", "set output file name", "NAME");

    opts.optflag("h", "help", "print this help menu");
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        return print_usage(&program, opts);
    }
    let (input, output) = match matches.free.len() {
        0 => return print_usage(&program, opts),
        1 => {
            let input = matches.free[0].clone();
            match matches.opt_str("o") {
                None => (input.clone(), input),
                Some(s) => (input, s),
            }
        }
        2 => (matches.free[0].clone(), matches.free[1].clone()),
        _ => return print_usage(&program, opts),
    };

    let keyfile = matches.opt_str("k").unwrap();

    let mut bytecode = Vec::new();
    File::open(&input)
        .unwrap()
        .read_to_end(&mut bytecode)
        .unwrap();

    let mut keybytes = Vec::new();
    File::open(&keyfile)
        .unwrap()
        .read_to_end(&mut keybytes)
        .unwrap();


    // Validate WASM module file
    let _module = to_module(bytecode.as_mut())
        .expect("Error, WASM module malformed");

    let config = Config::new();

    if matches.opt_present("v") {
        // verify signature
        let pkey = match to_public_key(keybytes.as_ref()) {
            Ok(key) => key,
            _ => {
                println!("Error: failed to parse public key from {}\n", keyfile);

                return print_usage(&program, opts);
            }
        };
        let retcode = match config.verify(&pkey, bytecode.as_ref()) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(WasmError::BadCipher) => {
                println!("Error, bad key cipher\n");
                1
            }
            Err(WasmError::BadVersion) => {
                println!("Error, bad encoded version in signature\n");
                1
            }
            Err(WasmError::NoSignature) => {
                println!("Error, no signature\n");
                1
            }
            Err(WasmError::MalformedModule) => {
                println!("Error, malformed WASM module {}\n", input);
                1
            }
            _ => {
                println!("Error, internal error\n");
                1
            }
        };
        ::std::process::exit(retcode);
    } else {
        // Sign
        let pkey = match to_private_key(keybytes.as_ref()) {
            Ok(key) => key,
            _ => {
                println!("Error: failed to parse private key from {}\n", keyfile);

                return print_usage(&program, opts);
            }
        };
        let retcode = match config.sign(&pkey, bytecode.as_ref()) {
            Ok(signed_bytecode) => {
                let mut owned = signed_bytecode;
                match File::create(&output) {
                    Ok(file) => {
                        let mut owned_file = file;
                        match owned_file.write_all(owned.as_mut()) {
                            Ok(_) => 0,
                            _ => {
                                println!("Error, write failure to {}\n", output);
                                1
                            }
                        }
                    }
                    _ => {
                        println!("Error, could not create output file {}\n", output);
                        1
                    }
                }
            }
            Err(WasmError::BadCipher) => {
                println!("Error, bad key cipher\n");
                1
            }
            Err(WasmError::MalformedModule) => {
                println!("Error, malformed wasm byte code\n");
                1
            }
            _ => {
                println!("Error, internal error\n");
                1
            }
        };

        ::std::process::exit(retcode);
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] <INPUT> [OUTPUT]", program);
    print!("{}", opts.usage(&brief));
    println!(
        "
A postprocessing command to sign/verify a wasm file.

Usage of this command typically looks like:

    # Sign a wasm file and write output to another file
    wasm-sign -k PRIVATE_KEY -o signed-foo.wasm foo.wasm

    # Verify the signature of a wasm file
    wasm-sign -v -k PUBLIC_KEY -o signed-foo.wasm foo.wasm

Please reports bugs to https://github.com/alexcrichton/wasm-gc if you find
them!
"
    );
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


    const WASM_BASE64: &str =
        "AGFzbQEAAAAADAZkeWxpbmuAgMACAAGKgICAAAJgAn9/AX9gAAACwYCAgAAEA2VudgptZW1vcnlCYXNl\
            A38AA2VudgZtZW1vcnkCAIACA2VudgV0YWJsZQFwAAADZW52CXRhYmxlQmFzZQN/AAOEgICAAAMAAQEGi\
            4CAgAACfwFBAAt/AUEACwejgICAAAIKX3RyYW5zZm9ybQAAEl9fcG9zdF9pbnN0YW50aWF0ZQACCYGAgI\
            AAAArpgICAAAPBgICAAAECfwJ/IABBAEoEQEEAIQIFIAAPCwNAIAEgAmoiAywAAEHpAEYEQCADQfkAOgA\
            ACyACQQFqIgIgAEcNAAsgAAsLg4CAgAAAAQuVgICAAAACQCMAJAIjAkGAgMACaiQDEAELCw==";

    #[test]
    fn test_to_private_key() {
        assert!(PRIVATE_KEY_SECP256K1.len() > 0);
        assert!(to_private_key(PRIVATE_KEY_SECP256K1).is_ok());
    }

    #[test]
    fn test_to_public_key() {
        assert!(PUBLIC_KEY_SECP256K1.len() > 0);
        assert!(to_public_key(PUBLIC_KEY_SECP256K1).is_ok());
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