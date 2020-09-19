use log::*;
use smol::Async;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::net;
use crate::slab::SlabsManagerSafe;
use crate::{get_current_time, Result};

type ConnectionsMap = async_dup::Arc<
    async_std::sync::Mutex<HashMap<SocketAddr, async_channel::Sender<net::Message>>>,
>;

type Clock = async_dup::Arc<AtomicU64>;

pub struct Protocol {
    slabman: SlabsManagerSafe,
    send_sx: async_channel::Sender<net::Message>,
    send_rx: async_channel::Receiver<net::Message>,
    connections: ConnectionsMap,
    main_process: Option<smol::Task<()>>,
}

impl Protocol {
    pub fn new(slabman: SlabsManagerSafe) -> Self {
        let (send_sx, send_rx) = async_channel::unbounded::<net::Message>();
        let connections = async_dup::Arc::new(async_std::sync::Mutex::new(HashMap::new()));
        Self {
            slabman,
            send_sx,
            send_rx,
            connections,
            main_process: None,
        }
    }

    pub fn get_send_pipe(&self) -> async_channel::Sender<net::Message> {
        self.send_sx.clone()
    }

    pub fn start(&mut self, address: SocketAddr) {
        let connections = self.connections.clone();
        let (send_sx, send_rx) = (self.send_sx.clone(), self.send_rx.clone());
        let slabman = self.slabman.clone();

        let titan_task = smol::Task::spawn(async move {
            loop {
                match Async::<TcpStream>::connect(address.clone()).await {
                    Ok(stream) => {
                        let _ = Self::handle_connect(
                            stream,
                            &connections,
                            address,
                            slabman.clone(),
                            (send_sx.clone(), send_rx.clone()),
                        )
                        .await;
                    }
                    Err(err) => warn!("Unable to connect. Retrying: {}", err),
                }

                // Sleep 1 second, retry connect
                // Eventually we will have more complex connection strategies
                // This is temporary
                net::sleep(1).await;
            }
        });
        self.main_process = Some(titan_task);
    }

    pub async fn stop(&mut self) {
        let main_process = std::mem::replace(&mut self.main_process, None);
        match main_process {
            Some(process) => {
                process.cancel().await;
            }
            None => {}
        }
    }

    async fn handle_connect(
        stream: Async<TcpStream>,
        connections: &ConnectionsMap,
        address: SocketAddr,
        slabman: SlabsManagerSafe,
        (send_sx, send_rx): (
            async_channel::Sender<net::Message>,
            async_channel::Receiver<net::Message>,
        ),
    ) -> Result<()> {
        let stream = async_dup::Arc::new(stream);

        connections
            .lock()
            .await
            .insert(address.clone(), send_sx.clone());

        send_sx
            .send(net::Message::GetSlabs(net::GetSlabsMessage {
                start_height: slabman.lock().await.last_height() + 1,
                end_height: 100000,
            }))
            .await?;

        // Run event loop
        match Self::event_loop_process(stream, slabman, connections, (send_sx, send_rx), &address)
            .await
        {
            Ok(()) => {
                warn!("Server timeout");
            }
            Err(err) => {
                warn!("Server disconnected: {}", err);
            }
        }

        connections.lock().await.remove(&address);
        Ok(())
    }

    async fn event_loop_process(
        mut stream: net::AsyncTcpStream,
        slabman: SlabsManagerSafe,
        _connections: &ConnectionsMap,
        (send_sx, send_rx): (
            async_channel::Sender<net::Message>,
            async_channel::Receiver<net::Message>,
        ),
        _self_addr: &SocketAddr,
    ) -> Result<()> {
        let inactivity_timer = net::InactivityTimer::new();

        let clock = async_dup::Arc::new(AtomicU64::new(0));
        let ping_task = smol::Task::spawn(Self::repeat_ping(send_sx.clone(), clock.clone()));

        loop {
            let event = net::select_event(&mut stream, &send_rx, &inactivity_timer).await?;

            match event {
                net::Event::Send(message) => {
                    net::send_message(&mut stream, message).await?;
                }
                net::Event::Receive(message) => {
                    inactivity_timer.reset().await?;
                    Self::protocol(message, &send_sx, &clock, &slabman).await?;
                }
                net::Event::Timeout => break,
            }
        }

        ping_task.cancel().await;
        inactivity_timer.stop().await;

        // Connection timed out
        Ok(())
    }

    async fn protocol(
        message: net::Message,
        send_sx: &async_channel::Sender<net::Message>,
        clock: &Clock,
        slabman: &SlabsManagerSafe,
    ) -> Result<()> {
        match message {
            net::Message::Ping => {
                // Ignore this message
            }
            net::Message::Pong => {
                let current_time = get_current_time();
                let elapsed = current_time - clock.load(Ordering::Relaxed);
                info!("Ping time: {} ms", elapsed);
            }
            net::Message::Put(_message) => {
                //let message = df::net::PutMessage::decode(Cursor::new(packet.payload))?;
                // Ignore this message
            }
            net::Message::Inv(inv) => {
                // Store in index
                //debug!("Received inv at height={}", inv.height);
                let mut slabman = slabman.lock().await;
                if slabman.has_unsorted_inv(inv.height) {
                    //debug!("Skipping already stored inv {}", inv.height);
                    return Ok(());
                }
                // Code below can maybe be simplified/more elegant. Requires thinking though.
                if !slabman.has_cipher_hash(&inv.cipher_hash) {
                    //debug!(
                    //    "Fetching missing ciphertext {}",
                    //    hex::encode(inv.cipher_hash)
                    //);
                    send_sx
                        .send(net::Message::GetCiphertext(net::GetCiphertextMessage {
                            cipher_hash: inv.cipher_hash.clone(),
                        }))
                        .await?;
                    // No point organizing since we know the ciphertext is missing
                    slabman.put_unsorted_inv(inv);
                } else if inv.height > slabman.last_height() {
                    slabman.put_unsorted_inv(inv);
                    slabman.organize().await;
                }

                if slabman.invs_are_missing() {
                    //debug!(
                    //    "Fetching missing invs from height {}",
                    //    slabman.last_height() + 1
                    //);
                    send_sx
                        .send(net::Message::GetSlabs(net::GetSlabsMessage {
                            start_height: slabman.last_height() + 1,
                            end_height: slabman.min_missing_inv_height() - 1,
                        }))
                        .await?;
                }
            }
            net::Message::GetSlabs(_message) => {
                // Ignore this message
            }
            net::Message::GetCiphertext(_message) => {
                // Ignore this message
            }
            net::Message::Ciphertext(ciphertext) => {
                // Add to local index
                let mut slabman = slabman.lock().await;
                slabman.put_ciphertext(ciphertext.ciphertext);
                slabman.organize().await;
                //debug!(
                //    "Added missing ciphertext. Store now at {}",
                //    slabman.last_height()
                //);
            }
        }

        Ok(())
    }

    // Clients send repeated pings. Servers only respond with pong.
    async fn repeat_ping(send_sx: async_channel::Sender<net::Message>, clock: Clock) -> Result<()> {
        loop {
            // Send ping
            send_sx.send(net::Message::Ping).await?;
            //debug!("send Message::Ping");
            clock.store(get_current_time(), Ordering::Relaxed);

            net::sleep(5).await;
        }
    }
}
