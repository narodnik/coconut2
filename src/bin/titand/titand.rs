use futures::io;
use futures::prelude::*;
use log::*;
use simplelog::*;
use smol::{Async, Timer};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};

use std::time::Duration;

use darkwallet as df;

/*
 * The TITAN service.
 *
 * This is the precursor to our blockchain system. It is a simple centralized database consisting
 * of encrypted blobs that we call slabs.
 *
 * Each slab is encrypted for a single key. This is done through the DH crypto system.
 * Clients download the slab headers, derive their DH key and check whether it matches the scancode
 * field. If so then they also download the ciphertext (as well as some fake ones) for decrypting.
 * This method is anonymous and persistant.
 *
 * This centralized service will be replaced by a simple PoS system. The network protocol though
 * is already kind of similar to what we will implement.
 * It is stateless and async.
 */

/*
 * The TITAN service.
 *
 * This is the precursor to our blockchain system. It is a simple centralized database consisting
 * of encrypted blobs that we call slabs.
 *
 * Each slab is encrypted for a single key. This is done through the DH crypto system.
 * Clients download the slab headers, derive their DH key and check whether it matches the scancode
 * field. If so then they also download the ciphertext (as well as some fake ones) for decrypting.
 * This method is anonymous and persistant.
 *
 * This centralized service will be replaced by a simple PoS system. The network protocol though
 * is already kind of similar to what we will implement.
 * It is stateless and async.
 */

async fn _echo(mut stream: Async<TcpStream>) -> io::Result<()> {
    Timer::after(Duration::from_secs(5)).await;

    let mut command = [0u8; 1];
    stream.read_exact(&mut command).await?;

    println!("read succeeeded");
    Ok(())
}

type ConnectionsMap = async_dup::Arc<
    async_std::sync::Mutex<HashMap<SocketAddr, async_channel::Sender<df::net::Message>>>,
>;

async fn start() -> df::Result<()> {
    let slabman = df::SlabsManager::new();

    // Create a listener.
    let listener = Async::<TcpListener>::bind("127.0.0.1:7445")?;
    info!("Listening on {}", listener.get_ref().local_addr()?);

    let connections = async_dup::Arc::new(async_std::sync::Mutex::new(HashMap::new()));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("Accepted client: {}", peer_addr);
        let stream = async_dup::Arc::new(stream);

        // Channel (queue) for sending data to the client
        let (send_sx, send_rx) = async_channel::unbounded::<df::net::Message>();
        connections.lock().await.insert(peer_addr, send_sx.clone());

        let slabman2 = slabman.clone();
        let connections2 = connections.clone();

        smol::Task::spawn(async move {
            match process(
                stream,
                slabman2,
                connections2.clone(),
                (send_sx, send_rx),
                &peer_addr,
            )
            .await
            {
                Ok(()) => {
                    warn!("Peer {} timeout", peer_addr);
                }
                Err(err) => {
                    warn!("Peer {} disconnected: {}", peer_addr, err);
                }
            }
            connections2.lock().await.remove(&peer_addr);
        })
        .detach();
    }
}

async fn process(
    mut stream: df::net::AsyncTcpStream,
    slabman: df::SlabsManagerSafe,
    connections: ConnectionsMap,
    (send_sx, send_rx): (
        async_channel::Sender<df::net::Message>,
        async_channel::Receiver<df::net::Message>,
    ),
    _self_addr: &SocketAddr,
) -> df::Result<()> {
    let inactivity_timer = df::net::InactivityTimer::new();

    loop {
        let event = df::net::select_event(&mut stream, &send_rx, &inactivity_timer).await?;

        match event {
            df::net::Event::Send(message) => {
                df::net::send_message(&mut stream, message).await?;
            }
            df::net::Event::Receive(message) => {
                inactivity_timer.reset().await?;
                protocol(message, &send_sx, &slabman, &connections).await?;
            }
            df::net::Event::Timeout => break,
        }
    }

    inactivity_timer.stop().await;

    // Connection timed out
    Ok(())
}

async fn protocol(
    message: df::net::Message,
    send_sx: &async_channel::Sender<df::net::Message>,
    slabman: &df::SlabsManagerSafe,
    connections: &ConnectionsMap,
) -> df::Result<()> {
    match message {
        df::net::Message::Ping => {
            send_sx.send(df::net::Message::Pong).await?;
        }
        df::net::Message::Pong => {}
        df::net::Message::Put(message) => {
            //let message = df::net::PutMessage::decode(Cursor::new(packet.payload))?;
            let slab = df::Slab {
                ephem_public: message.ephem_public,
                scancode: message.scancode,
                ciphertext: message.ciphertext,
            };

            let height = {
                let mut slabman = slabman.lock().await;
                slabman.add(slab.clone());
                slabman.last_height()
            };
            debug!("Added new slab at height={}", height);
            for send_sx in connections.lock().await.values() {
                // Store in index
                send_sx
                    .send(df::net::Message::Inv(df::net::InvMessage {
                        height,
                        ephem_public: slab.ephem_public,
                        scancode: slab.scancode,
                        cipher_hash: slab.cipher_hash(),
                    }))
                    .await?;
            }
        }
        df::net::Message::Inv(_message) => {
            // Ignore this message
        }
        df::net::Message::GetSlabs(message) => {
            // Serve invs
            let slabman = slabman.lock().await;
            if message.start_height == 0 {
                return Err(df::Error::MalformedPacket);
            }
            let end_height = if slabman.last_height() < message.end_height {
                slabman.last_height()
            } else {
                message.end_height
            };
            // Fetch missing block headers
            for height in message.start_height..=end_height {
                send_sx
                    .send(df::net::Message::Inv(slabman.inv(height)))
                    .await?;
            }
        }
        df::net::Message::GetCiphertext(message) => {
            // Serve ciphertext
            let cipher_hash = message.cipher_hash;
            match slabman.lock().await.get_ciphertext(&cipher_hash) {
                Some(ciphertext) => {
                    send_sx
                        .send(df::net::Message::Ciphertext(df::net::CiphertextMessage {
                            ciphertext: ciphertext.clone(),
                        }))
                        .await?;
                }
                None => {
                    debug!(
                        "Ciphertext not found. Skipping {}",
                        hex::encode(cipher_hash)
                    );
                }
            }
        }
        df::net::Message::Ciphertext(_message) => {
            // Ignore this message
        }
    }

    Ok(())
}

fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
        WriteLogger::new(
            LevelFilter::Debug,
            Config::default(),
            std::fs::File::create("/tmp/dftitan.log").unwrap(),
        ),
    ])
    .unwrap();

    df::smol_auto_run(start());
}
