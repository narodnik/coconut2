use darkwallet::coconut::coconut::SecretKey;
use darkwallet::coconut::coconut::VerifyKey;
use futures::io;
use futures::prelude::*;
use log::*;
use serde_derive::{Deserialize, Serialize};
use simplelog::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use darkwallet as df;
use darkwallet::serial::{Decodable, DecodableWithParams, Encodable};
use df::bls_extensions::*;
use df::schema::{Input, InputSecret};
use df::BlsStringConversion;
use df::RandomScalar;
use std::marker::Unpin;

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

// begin config utils
fn default_config_dir() -> PathBuf {
<<<<<<< HEAD
    dirs::home_dir().unwrap().as_path().join(".darkwallet/")
}

fn config_filename(config_dir: &Path) -> PathBuf {
    config_dir.join("darkwallet.cfg")
=======
    dirs::home_dir().unwrap().as_path().join(".darkfutures/")
}

fn config_filename(config_dir: &Path) -> PathBuf {
    config_dir.join("darkfutures.cfg")
>>>>>>> 4c096fe3c74d5277b00f0d79c6bf4471cf077a05
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

// end config utils

// begin serialization utils
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
// end serialization utils

fn token_new_secret(config_dir: &Path, value: u64) -> Result<String> {
    let coconut = get_context(config_dir)?;
    let token_secret = df::TokenSecret::generate(value, &coconut);

    hex_repr(&token_secret)
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

fn tx_add_input(input_data_str: &str, tx_data_str: &str) -> Result<(String, u64)> {
    let input = obj_from_hex::<df::Input>(input_data_str)?;
    let mut tx = obj_from_hex::<df::Transaction>(tx_data_str)?;
    let input_id = tx.add_input(input);
    Ok((hex_repr(&tx).unwrap(), input_id as u64))
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

fn input_new(
    config_dir: &Path,
    verify_key: &str,
    token_secret: &str,
    token: &str,
) -> Result<(String, String)> {
    let coconut = get_context(config_dir)?;
    let verify_key = obj_from_hex::<df::VerifyKey>(verify_key)?;
    let token_secret = obj_from_hex::<df::TokenSecret>(token_secret)?;
    let token = obj_from_hex::<df::Token>(token)?;
    let (input, input_secret) = df::Input::new(&coconut, &verify_key, &token, &token_secret);
    Ok((hex_repr(&input).unwrap(), hex_repr(&input_secret).unwrap()))
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

fn output_new(config_dir: &Path, token_secret_str: &str) -> Result<(String, String)> {
    let coconut = get_context(config_dir)?;
    let token_secret = obj_from_hex::<df::TokenSecret>(token_secret_str)?;
    let (output, output_secret) = df::Output::new(&coconut, &token_secret);
    Ok((
        hex_repr(&output).unwrap(),
        hex_repr(&output_secret).unwrap(),
    ))
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

// end wallet/node functions

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut buf = String::new();
    let _ = reader.read_line(&mut buf).await?;
    Ok(buf.trim().to_string())
}

// begin chatter protocol
fn request_create_output(
    config_dir: &Path,
    reply_address: &df::bls::G1Projective,
    verify_key: &str,
    token_secret: &str,
    token: &str,
) -> String {
    let context = get_context(config_dir);

    let message = df::chatter::Message::CreateOutput(df::chatter::CreateOutputMessage {
        payment_id: df::bls::Scalar::new_random::<df::OsRngInstance>(),
        reply_address: *reply_address,
    });

    let mut buff = Cursor::new(Vec::new());
    df::chatter::write_packet(&mut buff, message.pack().unwrap()).unwrap();
    let encoded = hex::encode(&mut buff.get_mut());

    encoded
}

fn request_output(config_dir: &Path, verify_key: &str) -> String {
    let context = get_context(config_dir);
    let token = "hey dude!";
    let token_value = 110;
    let token_secret = token_new_secret(config_dir, token_value).unwrap();
    let (output, output_secret) = output_new(config_dir, &token_secret).unwrap();
    info!(
        "Created new output {} with secret {}",
        output, output_secret
    );

    let message = df::chatter::Message::Output(df::chatter::OutputMessage {
        payment_id: df::bls::Scalar::new_random::<df::OsRngInstance>(),
        output: output.as_bytes().to_vec(),
    });

    let mut buff = Cursor::new(Vec::new());
    df::chatter::write_packet(&mut buff, message.pack().unwrap()).unwrap();
    let encoded = hex::encode(&mut buff.get_mut());

    encoded
}
// end chatter protocol

fn print_menu() -> () {
    println!("[1] Show Details");
    println!("[2] Initiate Transaction Request");
    println!("[3] Send Setup Output");
    println!("[4] Commit Output");
    // println!("[5] Setup Verify Key");
    println!("[6] Quit");
}

async fn process(
    plaintext: String,
    send_sx: async_channel::Sender<df::net::Message>,
    config_dir: &std::path::Path,
    ephem_secret: &df::bls::Scalar,
    verify_key: &str,
) -> () {
    let message_bytes = hex::decode(plaintext.clone()).unwrap();
    let mut buffer = Cursor::new(message_bytes);
    let packet = df::chatter::read_packet(&mut buffer).unwrap();
    let mut cursor = Cursor::new(packet.payload);
    match packet.command {
        df::chatter::PacketType::CreateOutput => {
            println!("Create Output...");
            let message = df::chatter::CreateOutputMessage::decode(cursor).unwrap();
            info!("reply address: {}", message.reply_address.to_string());
            let shared_secret = df::derive_shared_secret(&message.reply_address, &ephem_secret);
            let scancode = df::create_scancode(&shared_secret);

            let response = request_output(config_dir, verify_key);
            info!("Request Output Payload: {}", response);
            let payload =
                df::aes_encrypt(&shared_secret, &message.reply_address, &response.as_bytes())
                    .unwrap();
            send_sx
                .send(df::net::Message::Put(df::net::PutMessage {
                    ephem_public: df::bls::G1Affine::from(message.reply_address),
                    scancode: scancode.clone(),
                    ciphertext: payload,
                }))
                .await
                .unwrap();
        }
        df::chatter::PacketType::Output => {
            println!("Output...");
            let message = df::chatter::OutputMessage::decode(cursor);
        }
        _ => {
            println!("Other");
        }
    };

    ()
}

async fn start(
    ephem_public: df::bls::G1Projective,
    ephem_secret: df::bls::Scalar,
) -> df::Result<()> {
    let beacon = df::net::fetch_beacon().await?;
    info!("Titan address: {}", beacon.titand_address);

    // fetch a mint list from adamd
    let mint_public = df::bls::G1Projective::from_string(
        "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");
    let mut verify_key = "95ca466a380311767cb190c701f55b1782c440a3bb8a5f7e442c7e22536edc4ee27ed97ea5aa09c7302e629877a7a46c10e499958daa82cc8e0745035da15d9bcd774a75ed19082d950aa9bd8ac0c4211dc8fe519538344ab84d54eb4d8ecedf02973e14d10fdff03e71a6c080e4dcf3737ebdc969fa3b10cb0de26f4e7f0f04e6bb479e107f9b05a17bed86049b1d1ec91208cdb049cff87c77a88ebe006d02524c14250517881c1eda1c96030260943b8fa3106ac59ee2a04f6b56c89c95e88396e01c34c7926f426763541e09c092c52fdde4319fd33fc378b7b02c87b439bb222e19e1bd2bcc41466b165a1144b72117a2dc1591daed032fce62fd6cc16c06cd39351ab566d00fd077d1eb8543c995a9ea3e21187dd8fc10121d2742d7d7d9";

    let slabman = df::SlabsManager::new();
    let (slab_sx, slab_rx) = async_channel::unbounded::<(u32, df::Slab)>();
    let mut protocol = df::protocol::Protocol::new(slabman.clone());
    let mut protocol_listen = df::protocol::Protocol::new(slabman.clone());

    slabman.lock().await.subscribe(slab_sx);
    protocol.start(beacon.titand_address);
    protocol_listen.start(beacon.titand_address);

    let send_sx = protocol.get_send_pipe();

    let listen_slabs = smol::Task::spawn(async move {
        let mut default_config = default_config_dir();
        let config_dir = default_config.as_path();
        loop {
            match slab_rx.recv().await {
                Ok((slab_height, slab)) => {
                    info!("NEW SLAB! {}", slab_height);
                    let ephem_public = df::bls::G1Projective::from(&slab.ephem_public);
                    let shared_secret = df::derive_shared_secret(&ephem_public, &ephem_secret);
                    let scancode = df::create_scancode(&shared_secret);
                    if slab.scancode == scancode {
                        info!("Slab is for us!");
                        match df::aes_decrypt(&shared_secret, &ephem_public, &slab.ciphertext) {
                            Some(plaintext) => {
                                let value = std::str::from_utf8(&plaintext[..]).unwrap();
                                process(
                                    value.to_string(),
                                    send_sx.clone(),
                                    config_dir,
                                    &ephem_secret,
                                    verify_key,
                                )
                                .await;
                            }
                            None => {
                                info!("None");
                            }
                        }
                    }
                }
                Err(_) => {
                    info!("Error");
                    break;
                }
            }
        }
    });

    // menu
    let stdin = smol::reader(std::io::stdin());
    let mut stdin = io::BufReader::new(stdin);
    let send_sx = protocol.get_send_pipe();
    let mut default_config = default_config_dir();
    let config_dir = default_config.as_path();
    protocol.start(beacon.titand_address);
    'menu_select: loop {
        print_menu();

        let buf = read_line(&mut stdin).await.unwrap();

        match &buf[..] {
            "1" => {
                info!("Titan Address: {}", beacon.titand_address);
                info!("Mint Public Key: {}", mint_public.to_string());
                info!("Mint Verify Key: {}", hex::encode(&verify_key));
                info!("Network Secret: {}", ephem_secret.to_string());
                info!("Network Public: {}", ephem_public.to_string());
                let shared_secret = df::derive_shared_secret(&mint_public, &ephem_secret);
                let scancode = df::create_scancode(&shared_secret);
                let send_sx = protocol.get_send_pipe();
                let payload =
                    df::aes_encrypt(&shared_secret, &ephem_public, b"ahoy there!").unwrap();
                send_sx
                    .send(df::net::Message::Put(df::net::PutMessage {
                        ephem_public: df::bls::G1Affine::from(ephem_public),
                        scancode: scancode.clone(),
                        ciphertext: payload,
                    }))
                    .await
                    .unwrap();
                debug!("Send shite over");
            }
            "2" => {
                println!("Please enter destination public address or blank to return: ");
                let buf = read_line(&mut stdin).await;
                let opt = buf.unwrap().to_string();
                if opt.is_empty() {
                    break 'menu_select;
                }
                let dest_public = df::bls::G1Projective::from_string(&opt);
                let shared_secret = df::derive_shared_secret(&dest_public, &ephem_secret);
                let scancode = df::create_scancode(&shared_secret);
                info!("shared_secret: {}", hex::encode(&shared_secret));
                info!("scancode: {}", hex::encode(&scancode));

                let token = "token"; // TODO get from ...
                let token_value = 110;
                let token_secret = token_new_secret(config_dir, token_value).unwrap();
                let message = request_create_output(
                    config_dir,
                    &ephem_public,
                    &verify_key,
                    &token_secret,
                    token,
                );
                let payload =
                    df::aes_encrypt(&shared_secret, &ephem_public, message.as_bytes()).unwrap();

                let send_sx = protocol.get_send_pipe();
                send_sx
                    .send(df::net::Message::Put(df::net::PutMessage {
                        ephem_public: df::bls::G1Affine::from(ephem_public),
                        scancode: scancode.clone(),
                        ciphertext: payload.clone(),
                    }))
                    .await
                    .unwrap();
            }
            "6" => break 'menu_select,
            _ => {}
        }
    }

    Ok(())
}

fn main() -> df::Result<()> {
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
        WriteLogger::new(
            LevelFilter::Debug,
            Config::default(),
            std::fs::File::create("/tmp/dfclient.log").unwrap(),
        ),
    ])
    .unwrap();

    info!("Started client.");

    // Init user credentials
    let g1 = df::bls::G1Affine::generator();
    let ephem_secret = df::bls::Scalar::new_random::<df::OsRngInstance>();
    let ephem_public = g1 * ephem_secret;

    smol::run(start(ephem_public.clone(), ephem_secret.clone()))
}
