use futures::prelude::*;
use log::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use smol::{Async, Timer};

use std::convert::TryFrom;
use std::io;
use std::io::Cursor;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::async_serial::{AsyncReadExt, AsyncWriteExt};
use crate::bls;
use crate::error::{Error, Result};
use crate::serial::{Decodable, Encodable, VarInt};

const MAGIC_BYTES: [u8; 4] = [0xd9, 0xef, 0xb6, 0x7d];

pub type AsyncTcpStream = async_dup::Arc<Async<TcpStream>>;

pub type Ciphertext = Vec<u8>;
pub type CiphertextHash = [u8; 32];

// Packets and Message because Rust doesn't allow value
// aliasing from ADL type enums (which Message uses).
#[derive(IntoPrimitive, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum PacketType {
    Ping = 0,
    Pong = 1,
    Put = 2,
    Inv = 3,
    GetSlabs = 4,
    GetCiphertext = 5,
    Ciphertext = 6,
}

pub enum Message {
    // Sent by client every N minutes
    Ping,
    // Server responds back with Ping.
    // Ping and Pong are keepalive messages. Connection is dropped after period of inactivity.
    Pong,
    // Put a new slab in the blockchain.
    Put(PutMessage),
    // New slab registered in the blockchain.
    Inv(InvMessage),
    // Get slab inv messages to update local chain.
    GetSlabs(GetSlabsMessage),
    // Get actual ciphertext for a given inv message
    GetCiphertext(GetCiphertextMessage),
    // Cipertext response by the server
    Ciphertext(CiphertextMessage),
}

impl Message {
    pub fn pack(&self) -> Result<Packet> {
        match self {
            Message::Ping => Ok(Packet {
                command: PacketType::Ping,
                payload: Vec::new(),
            }),
            Message::Pong => Ok(Packet {
                command: PacketType::Pong,
                payload: Vec::new(),
            }),
            Message::Put(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::Put,
                    payload,
                })
            }
            Message::Inv(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::Inv,
                    payload,
                })
            }
            Message::GetSlabs(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::GetSlabs,
                    payload,
                })
            }
            Message::GetCiphertext(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::GetCiphertext,
                    payload,
                })
            }
            Message::Ciphertext(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::Ciphertext,
                    payload,
                })
            }
        }
    }

    pub fn unpack(packet: Packet) -> Result<Self> {
        let cursor = Cursor::new(packet.payload);
        match packet.command {
            PacketType::Ping => Ok(Self::Ping),
            PacketType::Pong => Ok(Self::Pong),
            PacketType::Put => Ok(Self::Put(PutMessage::decode(cursor)?)),
            PacketType::Inv => Ok(Self::Inv(InvMessage::decode(cursor)?)),
            PacketType::GetSlabs => Ok(Self::GetSlabs(GetSlabsMessage::decode(cursor)?)),
            PacketType::GetCiphertext => {
                Ok(Self::GetCiphertext(GetCiphertextMessage::decode(cursor)?))
            }
            PacketType::Ciphertext => Ok(Self::Ciphertext(CiphertextMessage::decode(cursor)?)),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Message::Ping => "Ping",
            Message::Pong => "Pong",
            Message::Put(_) => "Put",
            Message::Inv(_) => "Inv",
            Message::GetSlabs(_) => "GetSlabs",
            Message::GetCiphertext(_) => "GetCiphertext",
            Message::Ciphertext(_) => "Ciphertext",
        }
    }
}

// Packets are the base type read from the network
// These are converted to messages and passed to event loop
pub struct Packet {
    pub command: PacketType,
    pub payload: Vec<u8>,
}

// Put a new slab in the blockchain
pub struct PutMessage {
    // This is ephemeral public key used in DH algorithm
    pub ephem_public: bls::G1Affine,
    // Hash of the shared secret key
    // First 4 bytes of sha256 (see client.rs for example)
    pub scancode: [u8; 4],
    // The encrypted message we are sending
    pub ciphertext: Ciphertext,
}

// Sent by the server when a new slab is accepted
pub struct InvMessage {
    // Height of the slab
    pub height: u32,
    // Header field interpreted by the client
    // If they derive using their private key with DH
    // the same value as scancode then download the ciphertext.
    pub ephem_public: bls::G1Affine,
    pub scancode: [u8; 4],
    // Hash of the cipertext. This was clients avoid downloading
    // unncessary data they cannot decrypt.
    pub cipher_hash: CiphertextHash,
}

// Request missing invs starting from start_height
// Will be replaced by a block locator type.
pub struct GetSlabsMessage {
    pub start_height: u32,
    pub end_height: u32,
}

// Get ciphertext data
pub struct GetCiphertextMessage {
    pub cipher_hash: CiphertextHash,
}

// Cipertext data
pub struct CiphertextMessage {
    pub ciphertext: Ciphertext,
}

impl Encodable for PutMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.ephem_public.encode(&mut s)?;
        len += self.scancode.encode(&mut s)?;
        len += self.ciphertext.encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for PutMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            ephem_public: Decodable::decode(&mut d)?,
            scancode: Decodable::decode(&mut d)?,
            ciphertext: Decodable::decode(d)?,
        })
    }
}

impl Encodable for InvMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.height.encode(&mut s)?;
        len += self.ephem_public.encode(&mut s)?;
        len += self.scancode.encode(&mut s)?;
        len += self.cipher_hash.encode(s)?;
        Ok(len)
    }
}

impl Decodable for InvMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            height: Decodable::decode(&mut d)?,
            ephem_public: Decodable::decode(&mut d)?,
            scancode: Decodable::decode(&mut d)?,
            cipher_hash: Decodable::decode(d)?,
        })
    }
}

impl Encodable for GetSlabsMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let len = self.start_height.encode(&mut s)?;
        Ok(len + self.end_height.encode(s)?)
    }
}

impl Decodable for GetSlabsMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            start_height: Decodable::decode(&mut d)?,
            end_height: Decodable::decode(d)?,
        })
    }
}

impl Encodable for GetCiphertextMessage {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        self.cipher_hash.encode(s)
    }
}

impl Decodable for GetCiphertextMessage {
    fn decode<D: io::Read>(d: D) -> Result<Self> {
        Ok(Self {
            cipher_hash: Decodable::decode(d)?,
        })
    }
}

impl Encodable for CiphertextMessage {
    fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
        self.ciphertext.encode(s)
    }
}

impl Decodable for CiphertextMessage {
    fn decode<D: io::Read>(d: D) -> Result<Self> {
        Ok(Self {
            ciphertext: Decodable::decode(d)?,
        })
    }
}

pub async fn read_packet(stream: &mut AsyncTcpStream) -> Result<Packet> {
    // Packets have a 4 byte header of magic digits
    // This is used for network debugging
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic).await?;
    //debug!("read magic {:?}", magic);
    if magic != MAGIC_BYTES {
        return Err(Error::MalformedPacket);
    }

    // The type of the message
    let command = AsyncReadExt::read_u8(stream).await?;
    //debug!("read command: {}", command);
    let command = PacketType::try_from(command).map_err(|_| Error::MalformedPacket)?;

    let payload_len = VarInt::decode_async(stream).await?.0 as usize;

    // The message-dependent data (see message types)
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    Ok(Packet { command, payload })
}

pub async fn send_packet(stream: &mut AsyncTcpStream, packet: Packet) -> Result<()> {
    stream.write_all(&MAGIC_BYTES).await?;

    AsyncWriteExt::write_u8(stream, packet.command as u8).await?;

    assert_eq!(std::mem::size_of::<usize>(), std::mem::size_of::<u64>());
    VarInt(packet.payload.len() as u64)
        .encode_async(stream)
        .await?;

    stream.write_all(&packet.payload).await?;

    Ok(())
}

async fn receive_message(stream: &mut AsyncTcpStream) -> Result<Message> {
    let packet = read_packet(stream).await?;
    let message = Message::unpack(packet)?;
    debug!("received Message::{}", message.name());
    Ok(message)
}

pub async fn send_message(stream: &mut AsyncTcpStream, message: Message) -> Result<()> {
    debug!("sending Message::{}", message.name());
    let packet = message.pack()?;
    send_packet(stream, packet).await
}

// Eventloop event
pub enum Event {
    // Message to be sent from event queue
    Send(Message),
    // Received message to process by protocol
    Receive(Message),
    // Connection ping-pong timeout
    Timeout,
}

pub async fn select_event(
    stream: &mut AsyncTcpStream,
    send_rx: &async_channel::Receiver<Message>,
    inactivity_timer: &InactivityTimer,
) -> Result<Event> {
    Ok(futures::select! {
        message = send_rx.recv().fuse() => Event::Send(message?),
        message = receive_message(stream).fuse() => Event::Receive(message?),
        _ = inactivity_timer.wait_for_wakeup().fuse() => Event::Timeout
    })
}

/*
pub async fn unpack_request(payload: Vec<u8>) -> Result<Request> {
    let mut cursor = std::io::Cursor::new(payload);
    let action = cursor.read_u8()?;
    let action = RequestType::try_from(action).map_err(|_| Error::MalformedPacket)?;
    let id = cursor.read_u32()?;
    let params = Vec::decode(&mut cursor)?;
    Ok(Request { action, id, params })
}

pub async fn pack_request(request: Request) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.write_u8(request.action as u8)?;
    buffer.write_u32(request.id)?;
    request.params.encode(&mut buffer)?;
    Ok(buffer)
}

pub async fn unpack_reply(payload: Vec<u8>) -> Result<Reply> {
    let mut cursor = std::io::Cursor::new(payload);
    let id = cursor.read_u32()?;
    let status = cursor.read_u8()?;
    let status = ReplyErrorStatus::try_from(status).map_err(|_| Error::MalformedPacket)?;
    let result = Vec::decode(&mut cursor)?;
    Ok(Reply { id, status, result })
}
*/

pub async fn sleep(seconds: u64) {
    Timer::after(Duration::from_secs(seconds)).await;
}

// Used for ping pong loop timer
pub struct InactivityTimer {
    reset_sender: async_channel::Sender<()>,
    timeout_receiver: async_channel::Receiver<()>,
    task: smol::Task<()>,
}

impl InactivityTimer {
    pub fn new() -> Self {
        let (reset_sender, reset_receiver) = async_channel::bounded::<()>(1);
        let (timeout_sender, timeout_receiver) = async_channel::bounded::<()>(1);

        let task = smol::Task::spawn(async {
            match Self::_start(reset_receiver, timeout_sender).await {
                Ok(()) => {}
                Err(err) => error!("InactivityTimer fatal error {}", err),
            }
        });

        Self {
            reset_sender,
            timeout_receiver,
            task,
        }
    }

    pub async fn stop(self) {
        self.task.cancel().await;
    }

    // This loop basically waits for 10 secs. If it doesn't
    // receive a signal that something happened then it will
    // send a timeout signal. This will wakeup the main event loop
    // and the connection will be dropped.
    async fn _start(
        reset_rx: async_channel::Receiver<()>,
        timeout_sx: async_channel::Sender<()>,
    ) -> Result<()> {
        loop {
            let is_awake = futures::select! {
                _ = reset_rx.recv().fuse() => true,
                _ = sleep(10).fuse() => false
            };

            if !is_awake {
                warn!("InactivityTimer timeout");
                timeout_sx.send(()).await?;
            }
        }
    }

    pub async fn reset(&self) -> Result<()> {
        self.reset_sender.send(()).await?;
        Ok(())
    }

    pub async fn wait_for_wakeup(&self) -> Result<()> {
        Ok(self.timeout_receiver.recv().await?)
    }
}

pub struct Beacon {
    pub titand_address: SocketAddr,
}

pub async fn fetch_beacon() -> Result<Beacon> {
    let mut stream = Async::<TcpStream>::connect("127.0.0.1:7444").await?;
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;

    let address = String::decode(&buffer[..])?;
    Ok(Beacon {
        titand_address: address.parse()?,
    })
}
