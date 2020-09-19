use futures::prelude::*;
use log::*;
use smol::Async;
use std::net::TcpListener;

use darkwallet as df;
use df::Encodable;

/*
 * The ADAM process.
 *
 * Very simple seed daemon which gives nodes a topology of vital services in the network.
 * For now it just contains the TITAN service, but later there will be other additional ones.
 */

async fn start() -> df::Result<()> {
    let titand_address = "127.0.0.1:7445".to_string();

    let mut data: Vec<u8> = Vec::new();
    titand_address.encode(&mut data)?;

    // Create a listener.
    let listener = Async::<TcpListener>::bind("127.0.0.1:7444")?;
    info!("Listening on {}", listener.get_ref().local_addr()?);

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;
        info!("Accepted client: {}", peer_addr);

        match stream.write_all(&data).await {
            Ok(()) => debug!("Sent service locations"),
            Err(err) => warn!("Send failed: {}", err),
        }
    }
}

fn main() {
    df::smol_auto_run(start());
}
