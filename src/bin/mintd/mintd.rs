use darkwallet::serial::Encodable;
use futures::io;
use futures::prelude::*;
use log::*;
use simplelog::*;

use darkwallet as df;
//use df::RandomScalar;
use df::BlsStringConversion;

fn hex_repr<O: Encodable>(object: &O) -> io::Result<String> {
    let mut data: Vec<u8> = vec![];
    object.encode(&mut data);
    Ok(hex::encode(data))
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut buf = String::new();
    let _ = reader.read_line(&mut buf).await?;
    Ok(buf.trim().to_string())
}

async fn start() -> df::Result<()> {
    let g1 = df::bls::G1Affine::generator();
    //let secret = df::bls::Scalar::new_random::<df::OsRngInstance>();
    let secret = df::bls::Scalar::from_string(
        "847e156ee9f5ae920d8930153a47d52e4e9b28f74f200482d4dd65756ffd4706",
    );
    let public = g1 * secret;
    info!("Secret: {}", secret.to_string());
    info!("Public: {}", public.to_string());

    let number_attributes = 2;
    let threshold_service = 1;
    let total_services = 2;
    let (secret_keys, verify_key) =
        df::generate_keys(number_attributes, threshold_service, total_services);
    for (i, secret_key) in secret_keys.iter().enumerate() {
        println!("secret_key-{}: {}", i + 1, hex_repr(secret_key).unwrap());
    }
    println!(
        "Share the verify_key with nodes: {}",
        hex_repr(&verify_key).unwrap()
    );

    let beacon = df::net::fetch_beacon().await?;
    info!("Titan address: {}", beacon.titand_address);

    let mut slabman = df::SlabsManager::new();
    let (slab_sx, slab_rx) = async_channel::unbounded::<(u32, df::Slab)>();
    slabman.lock().await.subscribe(slab_sx);

    let mut protocol = df::protocol::Protocol::new(slabman.clone());
    protocol.start(beacon.titand_address);

    let listen_slabs = smol::Task::spawn(async move {
        loop {
            match slab_rx.recv().await {
                Ok((slab_height, slab)) => {
                    info!("NEW SLAB! {}", slab_height);
                    let ephem_public = df::bls::G1Projective::from(&slab.ephem_public);
                    let shared_secret = df::derive_shared_secret(&ephem_public, &secret);

                    let scancode = df::create_scancode(&shared_secret);

                    if slab.scancode == scancode {
                        info!("Slab is for us!");
                        match df::aes_decrypt(&shared_secret, &ephem_public, &slab.ciphertext) {
                            Some(plaintext) => {
                                info!(
                                    "Plaintext: {}",
                                    std::str::from_utf8(&plaintext[..]).unwrap()
                                );
                            }
                            None => {
                                warn!("This slab is actually not for us");
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let stdin = smol::reader(std::io::stdin());
    let mut stdin = io::BufReader::new(stdin);
    'menu_select: loop {
        println!("[1] Show Shared Key");
        println!("[2] Show All Keys (!!!)");
        println!("[3] Quit");

        let buf = read_line(&mut stdin).await?;

        match &buf[..] {
            "1" => println!("Verify Key: {}", hex_repr(&verify_key).unwrap()),
            "2" => {
                for (i, secret_key) in secret_keys.iter().enumerate() {
                    println!("secret_key-{}: {}", i + 1, hex_repr(secret_key).unwrap());
                }
            }
            "3" => break 'menu_select,
            _ => {}
        }
    }

    // 1. Add the protocol to mintd
    // 2. Add new receiver message queues to slabsmanager
    // 3. Start process listening for new slabs
    // 4. Check if slab is destined for us
    // 5. Decrypt ciphertext if slab is for us
    //
    // 6. Put all the df commands in the protocol with the mint

    listen_slabs.cancel().await;
    protocol.stop().await;

    Ok(())
}

fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
        WriteLogger::new(
            LevelFilter::Debug,
            Config::default(),
            std::fs::File::create("/tmp/dfmint.log").unwrap(),
        ),
    ])
    .unwrap();

    df::smol_auto_run(start());
}
