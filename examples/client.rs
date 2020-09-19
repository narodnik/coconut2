use futures::io;
use futures::prelude::*;
use log::*;
use simplelog::*;

use std::marker::Unpin;

use darkwallet as df;
use df::BlsStringConversion;

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut buf = String::new();
    let _ = reader.read_line(&mut buf).await?;
    Ok(buf.trim().to_string())
}

async fn menu() -> df::Result<()> {
    // I am just hacking here
    // There are many things mixed altogether right now

    // Code below is the code we need for BLS DH algorithm
    // I just needed to write it somewhere, and didn't get
    // time yet to make a proper API or organize anything.

    let stdin = smol::reader(std::io::stdin());
    let mut stdin = io::BufReader::new(stdin);

    let g1 = df::bls::G1Affine::generator();

    let mint_public = df::bls::G1Projective::from_string(
        "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

    // Sender
    // Create your secret and public keys

    //let ephem_secret = df::bls::Scalar::new_random::<df::OsRngInstance>();
    let ephem_secret = df::bls::Scalar::from_string(
        "d8a053e0527b7197bd004086d5894b79ac6ed199153a269ae199b8c21762565d",
    );
    let ephem_public = g1 * ephem_secret;

    // Sender creates derived secret key
    let shared_secret = df::derive_shared_secret(&mint_public, &ephem_secret);

    // This is the value a receiver can use to see whether
    // an encrypted ciphertext belongs to them.
    let scancode = df::create_scancode(&shared_secret);

    info!("ephem_secret: {}", ephem_secret.to_string());
    info!("ephem_public: {}", ephem_public.to_string());
    info!("shared_secret: {}", hex::encode(&shared_secret));
    info!("scancode: {}", hex::encode(&scancode));

    let ciphertext = df::aes_encrypt(&shared_secret, &ephem_public, b"hello1234").unwrap();

    let plaintext = df::aes_decrypt(&shared_secret, &ephem_public, &ciphertext).unwrap();
    // OK it works!
    assert_eq!(&plaintext, b"hello1234");

    // Send to titan:
    // emphem_public:48
    // scancode:4
    // ciphertext

    // This is our primitive block! (the slab data)

    // Find the TITAN address from ADAM
    let beacon = df::net::fetch_beacon().await?;
    info!("Address: {}", beacon.titand_address);

    // The primitive blockchain
    // Eventually this will be a PoS chain.
    // People will pay a token to put data inside.
    // For now it is a centralized single service
    let slabman = df::SlabsManager::new();

    let mut protocol = df::protocol::Protocol::new(slabman.clone());
    protocol.start(beacon.titand_address);

    let send_sx = protocol.get_send_pipe();

    // Menu screen
    'menu_select: loop {
        println!("[1] Send BTC");
        println!("[2] Quit");

        let buf = read_line(&mut stdin).await?;

        match &buf[..] {
            "1" => {
                // Send something
                send_sx
                    .send(df::net::Message::Put(df::net::PutMessage {
                        ephem_public: df::bls::G1Affine::from(ephem_public),
                        scancode: scancode.clone(),
                        ciphertext: ciphertext.clone(),
                    }))
                    .await?;
                debug!("Send shite over");
            }
            "2" => break 'menu_select,
            _ => {}
        }
    }

    protocol.stop().await;

    info!("Shutting down...");

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

    smol::run(menu())
}
