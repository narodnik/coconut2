#[macro_use]
extern crate clap;
use serde_derive::{Deserialize, Serialize};
use simplelog::*;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use darkwallet as df;
use darkwallet::serial::{Decodable, DecodableWithParams, Encodable};

type Result<T> = std::result::Result<T, failure::Error>;

type CoconutContext = df::Coconut<df::OsRngInstance>;

#[derive(Serialize, Deserialize)]
struct AppConfig {
    coconut: CoconutConfig,
}
#[derive(Serialize, Deserialize)]
struct CoconutConfig {
    number_attributes: u32,
    threshold: u32,
    total_services: u32,
}

fn hex_repr<O: Encodable>(object: &O) -> Result<String> {
    let mut data: Vec<u8> = vec![];
    object.encode(&mut data)?;
    Ok(hex::encode(data))
}

fn obj_from_hex<O: Decodable>(hex_str: &str) -> Result<O> {
    let data = hex::decode(hex_str)?;
    let object = O::decode(&data[..])?;
    Ok(object)
}

fn obj_from_hex_with_params<'a, O: DecodableWithParams<'a, df::OsRngInstance>>(
    coconut: &'a CoconutContext,
    hex_str: &str,
) -> Result<O> {
    let data = hex::decode(hex_str)?;
    let object = O::decode(&data[..], &coconut.params)?;
    Ok(object)
}

fn initialize(config_dir: &Path, threshold: u32, total: u32) -> Result<()> {
    let number_attributes = 2;

    let (secret_keys, verify_key) = df::generate_keys(number_attributes, threshold, total);

    for (i, secret_key) in secret_keys.iter().enumerate() {
        println!("secret_key-{}: {}", i + 1, hex_repr(secret_key)?);
    }

    println!("verify_key: {}", hex_repr(&verify_key)?);

    let config = AppConfig {
        coconut: CoconutConfig {
            number_attributes,
            threshold,
            total_services: total,
        },
    };
    save_config(config_dir, config)?;

    Ok(())
}

fn token_new_secret(config_dir: &Path, value: u64) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let token_secret = df::TokenSecret::generate(value, &coconut);
    println!("{}", hex_repr(&token_secret)?);
    Ok(())
}

fn tx_new() -> Result<()> {
    let tx = df::Transaction::new();
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_show(tx_data_str: &str) -> Result<()> {
    let tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    println!("withdraws: {}", tx.withdraws);
    println!("deposits: {}", tx.deposits);
    println!("inputs: {}", tx.inputs.len());
    println!("outputs: {}", tx.outputs.len());
    Ok(())
}

fn tx_add_deposit(value: u64, tx_data_str: &str) -> Result<()> {
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    tx.add_deposit(value);
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_add_withdraw(value: u64, tx_data_str: &str) -> Result<()> {
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    tx.add_withdraw(value);
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_add_input(input_data_str: &str, tx_data_str: &str) -> Result<()> {
    let input = obj_from_hex::<df::Input>(input_data_str)?;
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    let input_id = tx.add_input(input);
    println!("tx: {}", hex_repr(&tx)?);
    println!("input-id: {}", input_id);
    Ok(())
}

fn tx_add_output(output_data_str: &str, tx_data_str: &str) -> Result<()> {
    let output = obj_from_hex::<df::Output>(output_data_str)?;
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    let output_id = tx.add_output(output);
    println!("tx: {}", hex_repr(&tx)?);
    println!("output-id: {}", output_id);
    Ok(())
}

fn tx_compute_pedersens(
    config_dir: &Path,
    input_values: &Vec<u64>,
    output_values: &Vec<u64>,
    tx_data_str: &str,
) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    let (input_blinds, output_blinds) = tx.compute_pedersens(&coconut, input_values, output_values);
    for blind in &input_blinds {
        println!("input-blind: {}", hex_repr(blind)?);
    }
    for blind in &output_blinds {
        println!("output-blind: {}", hex_repr(blind)?);
    }

    println!("tx: {}", hex_repr(&tx)?);
    Ok(())
}

fn tx_set_input_proof(tx: &str, input_id: usize, input_proof: &str) -> Result<()> {
    let mut tx = obj_from_hex::<df::Transaction>(tx)?;
    let input_proof = obj_from_hex::<df::InputProofs>(input_proof)?;
    tx.inputs[input_id].set_proof(input_proof);
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_set_output_proof(tx: &str, output_id: usize, output_proof: &str) -> Result<()> {
    let mut tx = obj_from_hex::<df::Transaction>(tx)?;
    let output_proof = obj_from_hex::<df::OutputProofs>(output_proof)?;
    tx.outputs[output_id].set_proof(output_proof);
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_set_challenge(tx: &str, challenge: &str) -> Result<()> {
    let mut tx = obj_from_hex::<df::Transaction>(tx)?;
    let challenge = obj_from_hex::<df::bls::Scalar>(challenge)?;
    tx.challenge = challenge;
    println!("{}", hex_repr(&tx)?);
    Ok(())
}

fn tx_unblind(
    config_dir: &Path,
    tx: &str,
    token_secrets: &Vec<&df::TokenSecret>,
    signatures: Vec<Vec<df::OutputSignature>>,
) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let tx = obj_from_hex::<df::Transaction>(tx)?;
    if signatures.len() < coconut.threshold as usize {
        eprintln!("error: Not enough signatures");
        std::process::exit(-1);
    }
    let tokens = tx.unblind(&coconut, token_secrets, signatures);
    for token in &tokens {
        println!("{}", hex_repr(token)?);
    }
    Ok(())
}

fn input_new(config_dir: &Path, verify_key: &str, token_secret: &str, token: &str) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let token_secret = obj_from_hex::<df::TokenSecret>(token_secret)?;
    let token = obj_from_hex::<df::Token>(token)?;
    let (input, input_secret) = df::Input::new(&coconut, &verify_key, &token, &token_secret);
    println!("input: {}", hex_repr(&input)?);
    println!("input-secret: {}", hex_repr(&input_secret)?);
    Ok(())
}

fn input_setup_secret(
    config_dir: &Path,
    input_secret: &str,
    input_blind: &str,
    verify_key: &str,
) -> Result<()> {
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let coconut = get_context(config_dir)?;

    let mut input_secret = {
        let data = hex::decode(input_secret)?;
        let object =
            df::InputSecret::<df::OsRngInstance>::decode(&data[..], &coconut.params, &verify_key)?;
        object
    };
    let input_blind = obj_from_hex::<df::bls::Scalar>(input_blind)?;
    input_secret.setup(input_blind);
    println!("{}", hex_repr(&input_secret)?);
    Ok(())
}

fn input_commits(config_dir: &Path, input_secret: &str, verify_key: &str) -> Result<()> {
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let coconut = get_context(config_dir)?;
    let input_secret = {
        let data = hex::decode(input_secret)?;
        let object =
            df::InputSecret::<df::OsRngInstance>::decode(&data[..], &coconut.params, &verify_key)?;
        object
    };
    let input_proof_commits_hash = input_secret.proof_commits().hash();
    println!("{}", hex_repr(&input_proof_commits_hash)?);
    Ok(())
}

fn input_proof(
    config_dir: &Path,
    input_secret: &str,
    challenge: &str,
    verify_key: &str,
) -> Result<()> {
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let coconut = get_context(config_dir)?;
    let input_secret = {
        let data = hex::decode(input_secret)?;
        let object =
            df::InputSecret::<df::OsRngInstance>::decode(&data[..], &coconut.params, &verify_key)?;
        object
    };
    let challenge = obj_from_hex::<df::bls::Scalar>(challenge)?;
    let proofs = input_secret.finish(&challenge);
    println!("{}", hex_repr(&proofs)?);
    Ok(())
}

fn output_new(config_dir: &Path, token_secret_str: &str) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let token_secret = obj_from_hex::<df::TokenSecret>(token_secret_str)?;
    let (output, output_secret) = df::Output::new(&coconut, &token_secret);
    println!("output: {}", hex_repr(&output)?);
    println!("output-secret: {}", hex_repr(&output_secret)?);
    Ok(())
}

fn output_setup_secret(config_dir: &Path, output_secret: &str, output_blind: &str) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let mut output_secret =
        obj_from_hex_with_params::<df::OutputSecret<df::OsRngInstance>>(&coconut, output_secret)?;
    let output_blind = obj_from_hex::<df::bls::Scalar>(output_blind)?;
    output_secret.setup(output_blind);
    println!("{}", hex_repr(&output_secret)?);
    Ok(())
}

fn output_commits(config_dir: &Path, output_secret: &str) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let output_secret =
        obj_from_hex_with_params::<df::OutputSecret<df::OsRngInstance>>(&coconut, output_secret)?;
    let output_proof_commits_hash = output_secret.proof_commits().hash();
    println!("{}", hex_repr(&output_proof_commits_hash)?);
    Ok(())
}

fn output_proof(config_dir: &Path, output_secret: &str, challenge: &str) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let output_secret =
        obj_from_hex_with_params::<df::OutputSecret<df::OsRngInstance>>(&coconut, output_secret)?;
    let challenge = obj_from_hex::<df::bls::Scalar>(challenge)?;
    let proofs = output_secret.finish(&challenge);
    println!("{}", hex_repr(&proofs)?);
    Ok(())
}

fn run_service(config_dir: &Path, secret_key: &str, verify_key: &str, index: u64) -> Result<()> {
    let coconut = get_context(config_dir)?;
    let secret_key = obj_from_hex::<df::SecretKey>(secret_key)?;
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let mut service = df::SigningService::from_secret(&coconut, secret_key, verify_key, index);
    eprintln!("[service-{}] Started.", service.index);

    loop {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                eprintln!("[service-{}] Processing...", service.index);

                let input = input.trim();

                if input == "exit" {
                    eprintln!("[service-{}] Exit.", service.index);
                    std::process::exit(-1);
                }

                if let Ok(tx) = obj_from_hex::<df::Transaction>(&input) {
                    match service.process(&tx) {
                        Ok(signatures) => {
                            eprintln!(
                                "[service-{}] Signed {} tokens",
                                service.index,
                                signatures.len()
                            );

                            println!("{}", hex_repr(&signatures)?);
                        }
                        Err(err) => {
                            eprintln!("Error occured signing (service={}): {}", service.index, err);
                        }
                    }
                } else {
                    eprintln!("Invalid tx data");
                }
            }
            Err(err) => {
                eprintln!("Error reading stdin: {}", err);
                break;
            }
        }
    }

    Ok(())
}

fn default_config_dir() -> PathBuf {
    dirs::home_dir().unwrap().as_path().join(".darkwallet/")
}

fn config_filename(config_dir: &Path) -> PathBuf {
    config_dir.join("darkwallet.cfg")
}

fn save_config(config_dir: &Path, config: AppConfig) -> Result<()> {
    let mut file = File::create(config_filename(config_dir))?;
    let toml = toml::to_string(&config)?;
    file.write_all(toml.as_bytes())?;
    Ok(())
}

fn load_config(config_dir: &Path) -> Result<AppConfig> {
    let mut file = File::open(config_filename(config_dir))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: AppConfig = toml::from_str(&contents)?;
    Ok(config)
}

fn get_context(config_dir: &Path) -> Result<CoconutContext> {
    let config = load_config(config_dir)?;
    let coconut = CoconutContext::new(
        config.coconut.number_attributes,
        config.coconut.threshold,
        config.coconut.total_services,
    );
    Ok(coconut)
}

fn main() -> Result<()> {
    let matches = clap_app!(darkwallet =>
        (version: "0.1.0")
        (author: "Amir Taaki <amir@dyne.org>")
        (about: "Issue and manage dark transactions")
        (@arg CONFIG: -c --config +takes_value "Sets the config directory")
        (@subcommand init =>
            (about: "Initialize service authority keys")
            (@arg THRESHOLD: +required "Threshold m value")
            (@arg TOTAL: +required "Total number n services")
        )
        (@subcommand token =>
            (about: "Issue and manage tokens")
            (@subcommand ("new-secret") =>
                (about: "Create a new token secret")
                (@arg VALUE: +required "Amount stored in the token")
            )
        )
        (@subcommand tx =>
            (about: "Construct and examine transactions")
            (@subcommand new =>
                (about: "Create a new transaction")
            )
            (@subcommand show =>
                (about: "Display a transaction")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("add-deposit") =>
                (about: "Add a deposit to a transaction")
                (@arg VALUE: +required "Amount to add")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("add-withdraw") =>
                (about: "Add a withdraw to a transaction")
                (@arg VALUE: +required "Amount to add")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("add-input") =>
                (about: "Add an input to a transaction")
                (@arg INPUT: +required "Input to add")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("add-output") =>
                (about: "Add an output to a transaction")
                (@arg OUTPUT: +required "Output to add")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("compute-pedersens") =>
                (about: "Comput pedersen commits")
                (@arg INPUT_VALUE: -i --input ... "Input value")
                (@arg OUTPUT_VALUE: -o --output ... "Output value")
                (@arg TX: +required "Tx data")
            )
            (@subcommand ("set-input-proof") =>
                (about: "Set the proof for an input")
                (@arg TX: +required "Tx data")
                (@arg INPUT_ID: +required "Index of the input")
                (@arg INPUT_PROOF: +required "Input proof")
            )
            (@subcommand ("set-output-proof") =>
                (about: "Set the proof for an output")
                (@arg TX: +required "Tx data")
                (@arg OUTPUT_ID: +required "Index of the output")
                (@arg OUTPUT_PROOF: +required "Output proof")
            )
            (@subcommand ("set-challenge") =>
                (about: "Set the challenge field")
                (@arg TX: +required "Tx data")
                (@arg CHALLENGE: +required "Challenge value")
            )
            (@subcommand unblind =>
                (about: "Unblind threshold number of partial signatures into a single final signature")
                (@arg TX: +required "Tx data")
                (@arg TOKEN_SECRET: -t --token ... "Token secrets")
                (@arg OUTPUT_SIGNATURE: -s --signature ... "Partial blind signature")
            )
        )
        (@subcommand input =>
            (about: "Transaction input commands")
            (@subcommand new =>
                (about: "Create a new input")
                (@arg VERIFY_KEY: +required "Services verification key")
                (@arg TOKEN: +required "Token for input")
                (@arg TOKEN_SECRET: +required "Token secret for input")
            )
            (@subcommand ("setup-secret") =>
                (about: "Setup input secret with pedersen blind")
                (@arg VERIFY_KEY: +required "Services verification key")
                (@arg INPUT_SECRET: +required "Input secret")
                (@arg INPUT_BLIND: +required "Input blind")
            )
            (@subcommand commits =>
                (about: "Export input commits")
                (@arg VERIFY_KEY: +required "Services verification key")
                (@arg INPUT_SECRET: +required "Input secret")
            )
            (@subcommand proof =>
                (about: "Finalize proof")
                (@arg VERIFY_KEY: +required "Services verification key")
                (@arg INPUT_SECRET: +required "Input secret")
                (@arg CHALLENGE: +required "Challenge value")
            )
        )
        (@subcommand output =>
            (about: "Transaction output commands")
            (@subcommand new =>
                (about: "Create a new output")
                (@arg TOKEN_SECRET: +required "Token secret for output")
            )
            (@subcommand ("setup-secret") =>
                (about: "Setup output secret with pedersen blind")
                (@arg OUTPUT_SECRET: +required "Output secret")
                (@arg OUTPUT_BLIND: +required "Output blind")
            )
            (@subcommand commits =>
                (about: "Export output commits")
                (@arg OUTPUT_SECRET: +required "Output secret")
            )
            (@subcommand proof =>
                (about: "Finalize proof")
                (@arg OUTPUT_SECRET: +required "Output secret")
                (@arg CHALLENGE: +required "Challenge value")
            )
        )
        (@subcommand ("hash-challenge") =>
            (about: "Hash proof commits together and produce proof challenge")
            (@arg INPUT_PROOF_COMMIT: -i --input ... "Input proof commit hash")
            (@arg OUTPUT_PROOF_COMMIT: -o --output ... "Output proof commit hash")
        )
        (@subcommand ("run-service") =>
            (about: "Run a signing service. Reads from STDIN, outputs to STDOUT")
            (@arg SECRET_KEY: +required "Secret key for this service")
            (@arg VERIFY_KEY: +required "Verify key for all services combined")
            (@arg INDEX: +required "Service index. Always starts from 1 to N (inclusive)")
        )
    )
    .get_matches();

    let default_dir = default_config_dir();

    let config_dir = match matches.value_of("CONFIG") {
        None => default_dir.as_path(),
        Some(path_str) => Path::new(path_str),
    };

    if !config_dir.exists() {
        match std::fs::create_dir(config_dir) {
            Err(err) => {
                eprintln!("error: Creating config dir: {}", err);
                std::process::exit(-1);
            }
            Ok(()) => (),
        }
        println!("Initialized new config directory: {}", config_dir.display());
    }

    //let log_path = config_dir.join("darkwallet.log");

    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
        //WriteLogger::new(
        //    LevelFilter::Info,
        //    Config::default(),
        //    std::fs::File::create(log_path).unwrap(),
        //),
    ])
    .unwrap();

    match matches.subcommand() {
        ("init", Some(matches)) => {
            let threshold: u32 = matches.value_of("THRESHOLD").unwrap().parse()?;
            let total: u32 = matches.value_of("TOTAL").unwrap().parse()?;
            initialize(config_dir, threshold, total)?;
        }
        ("token", Some(token_matches)) => match token_matches.subcommand() {
            ("new-secret", Some(matches)) => {
                let value: u64 = matches.value_of("VALUE").unwrap().parse()?;
                token_new_secret(config_dir, value)?;
            }
            _ => {
                eprintln!("error: Invalid token subcommand invoked");
                std::process::exit(-1);
            }
        },
        ("tx", Some(tx_matches)) => match tx_matches.subcommand() {
            ("new", Some(_)) => {
                tx_new()?;
            }
            ("show", Some(matches)) => {
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_show(&tx)?;
            }
            ("add-deposit", Some(matches)) => {
                let value: u64 = matches.value_of("VALUE").unwrap().parse()?;
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_add_deposit(value, &tx)?;
            }
            ("add-withdraw", Some(matches)) => {
                let value: u64 = matches.value_of("VALUE").unwrap().parse()?;
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_add_withdraw(value, &tx)?;
            }
            ("add-input", Some(matches)) => {
                let input: String = matches.value_of("INPUT").unwrap().parse()?;
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_add_input(&input, &tx)?;
            }
            ("add-output", Some(matches)) => {
                let output: String = matches.value_of("OUTPUT").unwrap().parse()?;
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_add_output(&output, &tx)?;
            }
            ("compute-pedersens", Some(matches)) => {
                let mut inputs: Vec<u64> = vec![];
                if let Some(values) = matches.values_of("INPUT_VALUE") {
                    for value in values {
                        inputs.push(value.parse()?);
                    }
                }
                let mut outputs: Vec<u64> = vec![];
                if let Some(values) = matches.values_of("OUTPUT_VALUE") {
                    for value in values {
                        outputs.push(value.parse()?);
                    }
                }
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                tx_compute_pedersens(config_dir, &inputs, &outputs, &tx)?;
            }
            ("set-input-proof", Some(matches)) => {
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                let input_id: usize = matches.value_of("INPUT_ID").unwrap().parse()?;
                let input_proof: String = matches.value_of("INPUT_PROOF").unwrap().parse()?;
                tx_set_input_proof(&tx, input_id, &input_proof)?;
            }
            ("set-output-proof", Some(matches)) => {
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                let output_id: usize = matches.value_of("OUTPUT_ID").unwrap().parse()?;
                let output_proof: String = matches.value_of("OUTPUT_PROOF").unwrap().parse()?;
                tx_set_output_proof(&tx, output_id, &output_proof)?;
            }
            ("set-challenge", Some(matches)) => {
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                let challenge: String = matches.value_of("CHALLENGE").unwrap().parse()?;
                tx_set_challenge(&tx, &challenge)?;
            }
            ("unblind", Some(matches)) => {
                let tx: String = matches.value_of("TX").unwrap().parse()?;
                let mut token_secret_vals: Vec<df::TokenSecret> = vec![];
                if let Some(values) = matches.values_of("TOKEN_SECRET") {
                    for value in values {
                        token_secret_vals.push(obj_from_hex(value)?);
                    }
                }
                let token_secrets: Vec<&_> =
                    token_secret_vals.iter().map(|secret| secret).collect();
                let mut signatures: Vec<Vec<df::OutputSignature>> = vec![];
                if let Some(values) = matches.values_of("OUTPUT_SIGNATURE") {
                    for value in values {
                        let outsigs = obj_from_hex(value)?;
                        signatures.push(outsigs);
                    }
                }
                tx_unblind(config_dir, &tx, &token_secrets, signatures)?;
            }
            _ => {
                eprintln!("error: Invalid tx subcommand invoked");
                std::process::exit(-1);
            }
        },
        ("input", Some(input_matches)) => match input_matches.subcommand() {
            ("new", Some(matches)) => {
                let verify_key: String = matches.value_of("VERIFY_KEY").unwrap().parse()?;
                let token_secret: String = matches.value_of("TOKEN_SECRET").unwrap().parse()?;
                let token: String = matches.value_of("TOKEN").unwrap().parse()?;
                input_new(config_dir, &verify_key, &token_secret, &token)?;
            }
            ("setup-secret", Some(matches)) => {
                let verify_key: String = matches.value_of("VERIFY_KEY").unwrap().parse()?;
                let input_secret: String = matches.value_of("INPUT_SECRET").unwrap().parse()?;
                let input_blind: String = matches.value_of("INPUT_BLIND").unwrap().parse()?;
                input_setup_secret(config_dir, &input_secret, &input_blind, &verify_key)?;
            }
            ("commits", Some(matches)) => {
                let verify_key: String = matches.value_of("VERIFY_KEY").unwrap().parse()?;
                let input_secret: String = matches.value_of("INPUT_SECRET").unwrap().parse()?;
                input_commits(config_dir, &input_secret, &verify_key)?;
            }
            ("proof", Some(matches)) => {
                let verify_key: String = matches.value_of("VERIFY_KEY").unwrap().parse()?;
                let input_secret: String = matches.value_of("INPUT_SECRET").unwrap().parse()?;
                let challenge: String = matches.value_of("CHALLENGE").unwrap().parse()?;
                input_proof(config_dir, &input_secret, &challenge, &verify_key)?;
            }
            _ => {
                eprintln!("error: Invalid tx subcommand invoked");
                std::process::exit(-1);
            }
        },
        ("output", Some(output_matches)) => match output_matches.subcommand() {
            ("new", Some(matches)) => {
                let token_secret: String = matches.value_of("TOKEN_SECRET").unwrap().parse()?;
                output_new(config_dir, &token_secret)?;
            }
            ("setup-secret", Some(matches)) => {
                let output_secret: String = matches.value_of("OUTPUT_SECRET").unwrap().parse()?;
                let output_blind: String = matches.value_of("OUTPUT_BLIND").unwrap().parse()?;
                output_setup_secret(config_dir, &output_secret, &output_blind)?;
            }
            ("commits", Some(matches)) => {
                let output_secret: String = matches.value_of("OUTPUT_SECRET").unwrap().parse()?;
                output_commits(config_dir, &output_secret)?;
            }
            ("proof", Some(matches)) => {
                let output_secret: String = matches.value_of("OUTPUT_SECRET").unwrap().parse()?;
                let challenge: String = matches.value_of("CHALLENGE").unwrap().parse()?;
                output_proof(config_dir, &output_secret, &challenge)?;
            }
            _ => {
                eprintln!("error: Invalid tx subcommand invoked");
                std::process::exit(-1);
            }
        },
        ("hash-challenge", Some(matches)) => {
            let mut hasher = df::HasherToScalar::new();
            if let Some(commits) = matches.values_of("INPUT_PROOF_COMMIT") {
                for commit in commits {
                    let commit = obj_from_hex::<df::bls::Scalar>(commit)?;
                    hasher.add(commit);
                }
            }
            if let Some(commits) = matches.values_of("OUTPUT_PROOF_COMMIT") {
                for commit in commits {
                    let commit = obj_from_hex::<df::bls::Scalar>(commit)?;
                    hasher.add(commit);
                }
            }
            println!("{}", hex_repr(&hasher.finish())?);
        }
        ("run-service", Some(matches)) => {
            let secret_key: String = matches.value_of("SECRET_KEY").unwrap().parse()?;
            let verify_key: String = matches.value_of("VERIFY_KEY").unwrap().parse()?;
            let index: u64 = matches.value_of("INDEX").unwrap().parse()?;
            run_service(config_dir, &secret_key, &verify_key, index)?;
        }
        _ => {
            eprintln!("error: Invalid subcommand invoked");
            std::process::exit(-1);
        }
    }

    Ok(())
}
