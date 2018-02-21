extern crate env_logger;
extern crate getopts;
extern crate base64;
extern crate wasm_sign;
extern crate openssl;
extern crate parity_wasm;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::vec::Vec;
use openssl::ec::EcKey;
use openssl::pkey::PKey;
use openssl::error::ErrorStack;
use getopts::Options;
//use parity_wasm::elements::Error as ParityWasmError;
// use parity_wasm::deserialize_buffer;
use parity_wasm::elements::{
    Module,
    Error as ParityError,
    Deserialize,
};

use wasm_sign::{Error, Config};



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
            Ok(false) => {
                println!("no valid signature\n");
                1
            }
            Err(Error::BadCipher) => {
                println!("Error, bad key cipher\n");
                1
            }
            Err(Error::BadVersion) => {
                println!("Error, bad encoded version in signature\n");
                1
            }
            Err(Error::NoSignature) => {
                println!("Error, no signature\n");
                1
            }
            Err(Error::MalformedModule) => {
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
            Err(Error::BadCipher) => {
                println!("Error, bad key cipher\n");
                1
            }
            Err(Error::MalformedModule) => {
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

