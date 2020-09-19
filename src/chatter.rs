// This file is incomplete!
use crate::serial::VarInt;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::io;
use std::io::Cursor;

use crate::bls;
use crate::error::{Error, Result};
use crate::serial::{Decodable, Encodable};
use std::convert::TryFrom;
use std::convert::TryInto;

// use crate::bls_extensions::BlsStringConversion;

pub type PaymentId = bls::Scalar;
pub type ReplyAddress = bls::G1Projective;

// Packets and Message because Rust doesn't allow value
// aliasing from ADL type enums (which Message uses).
#[derive(IntoPrimitive, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum PacketType {
    CreateOutput = 0,
    Output = 1,
    SetupOutput = 2,
    OutputCommits = 3,
    CompleteOutputProof = 4,
    OutputProof = 5,
    RequestMinSign = 6,
    MintSignature = 7,
}

pub enum Message {
    // Create an output to initiate receive funds
    CreateOutput(CreateOutputMessage),
    // Output for receiving funds.
    Output(OutputMessage),
    // Perform setup phase and return proof commit values.
    SetupOutput(SetupOutputMessage),
}

impl Message {
    pub fn pack(&self) -> Result<Packet> {
        match self {
            Message::CreateOutput(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::CreateOutput,
                    payload,
                })
            }
            Message::Output(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::Output,
                    payload,
                })
            }
            Message::SetupOutput(message) => {
                let mut payload = Vec::new();
                message.encode(Cursor::new(&mut payload))?;
                Ok(Packet {
                    command: PacketType::SetupOutput,
                    payload,
                })
            }
        }
    }

    pub fn unpack(packet: Packet) -> Result<Self> {
        let mut cursor = Cursor::new(packet.payload);
        match packet.command {
            PacketType::CreateOutput => {
                println!("Create Output...");
                Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?))
            }
            PacketType::Output => {
                println!("Output...");
                Ok(Self::Output(OutputMessage::decode(cursor)?))
            }
            PacketType::SetupOutput => Ok(Self::SetupOutput(SetupOutputMessage::decode(cursor)?)),
            PacketType::OutputCommits => {
                Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?))
            }
            PacketType::CompleteOutputProof => {
                Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?))
            }
            PacketType::OutputProof => Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?)),
            PacketType::RequestMinSign => {
                Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?))
            }
            PacketType::MintSignature => {
                Ok(Self::CreateOutput(CreateOutputMessage::decode(cursor)?))
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Message::CreateOutput(_) => "CreateOutput",
            Message::Output(_) => "Output",
            Message::SetupOutput(_) => "SetupOutput",
        }
    }
}

pub struct Packet {
    pub command: PacketType,
    pub payload: Vec<u8>,
}

pub struct CreateOutputMessage {
    pub payment_id: PaymentId,
    pub reply_address: ReplyAddress,
}

pub struct OutputMessage {
    pub payment_id: PaymentId,
    pub output: Vec<u8>,
}

pub struct SetupOutputMessage {
    pub payment_id: PaymentId,
    pub blind_value: bls::Scalar,
    pub reply_address: ReplyAddress,
}

impl Encodable for CreateOutputMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.payment_id.encode(&mut s)?;
        len += self.reply_address.encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for CreateOutputMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            payment_id: Decodable::decode(&mut d)?,
            reply_address: Decodable::decode(&mut d)?,
        })
    }
}

impl Encodable for OutputMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.payment_id.encode(&mut s)?;
        len += self.output.encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for OutputMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            payment_id: Decodable::decode(&mut d)?,
            output: Decodable::decode(&mut d)?, // TODO varint
        })
    }
}

impl Encodable for SetupOutputMessage {
    fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
        let mut len = 0;
        len += self.payment_id.encode(&mut s)?;
        len += self.blind_value.encode(&mut s)?;
        len += self.reply_address.encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for SetupOutputMessage {
    fn decode<D: io::Read>(mut d: D) -> Result<Self> {
        Ok(Self {
            payment_id: Decodable::decode(&mut d)?,
            blind_value: Decodable::decode(&mut d)?,
            reply_address: Decodable::decode(&mut d)?,
        })
    }
}

pub fn write_packet<W: io::Write>(stream: &mut W, packet: Packet) -> Result<()> {
    stream.write(&[packet.command as u8])?;
    let v = VarInt(packet.payload.len() as u64);
    let mut buff = Cursor::new(Vec::new());
    let _size = match v.encode(&mut buff) {
        Ok(result) => result,
        Err(err) => {
            panic!("Cannot pack message {}", err);
        }
    };
    stream.write(&buff.get_ref()[0..1])?;
    stream.write(&packet.payload)?;
    Ok(())
}

pub fn read_packet<D: io::Read>(stream: &mut D) -> Result<Packet> {
    let mut command = [0u8; 1];
    stream.read_exact(&mut command)?;
    // println!("command {:?}", command[0]);
    let command = PacketType::try_from(command[0]).map_err(|_| Error::MalformedPacket)?;

    let mut len = [0u8; 1];
    stream.read_exact(&mut len)?;
    let v = VarInt(len[0] as u64);
    println!("len {:?}", v.0);
    let mut payload = vec![0u8; (v.0 as u64).try_into().unwrap()];
    stream.read_exact(&mut payload)?;
    println!("payload {:?}", payload);

    Ok(Packet { command, payload })
}

<<<<<<< HEAD
/*
=======
>>>>>>> 4c096fe3c74d5277b00f0d79c6bf4471cf077a05
#[cfg(test)]
mod chatter_test {
    use crate::bls_extensions::BlsStringConversion;
    use crate::serial::VarInt;
    use crate::RandomScalar;
    use std::io::Cursor;

    #[test]
    fn it_encodes_create_output_message() {
        let reply_addr = crate::bls::G1Projective::from_string(
            "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

        let message = crate::chatter::Message::CreateOutput(crate::chatter::CreateOutputMessage {
            payment_id: crate::bls::Scalar::from(18446744073709551615u64),
            reply_address: reply_addr,
        });

        let s = match message.pack() {
            Ok(value) => {
                // println!("{:?}", value.payload);
                value
            }
            Err(err) => {
                panic!("Cannot pack message {}", err);
            }
        };

        let mut buff = Cursor::new(Vec::new());
        crate::chatter::write_packet(&mut buff, s).unwrap();

        let encoded = hex::encode(&mut buff.get_mut());
        let expected = "0050ffffffffffffffff00000000000000000000000000000000000000000000000096ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7";
        assert_eq!(&encoded, &expected);
    }

    #[test]
    fn it_decodes_create_output_message() {
        let raw_message = "0050ffffffffffffffff00000000000000000000000000000000000000000000000096ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7";
        let message_bytes = hex::decode(raw_message).unwrap();
        let mut buffer = Cursor::new(message_bytes);
        let message = crate::chatter::read_packet(&mut buffer).unwrap();

        let expected_reply_addr = crate::bls::G1Projective::from_string(
            "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

        let mut payload = crate::chatter::Message::unpack(message).unwrap();
        if let crate::chatter::Message::CreateOutput(value) = payload {
            assert_eq!(expected_reply_addr, value.reply_address);
        };
    }

    #[test]
    fn it_encodes_output_message() {
        let output = "c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000081020ff6b0fc18349a8b79e5b40ef611ad048f47a52ffdc1649a0ea33dd68a8947760fc02f50401075aa25639331ebf002adb67c79cc40d2142f3af24c473e99fc1d3b999a334e87025e9f808f6685b8b59a74017c754b5db44abfb74ceff5a5ceb15dcaa39263dfd1aa9961af8acd83784ae633fbeaab2be2348fedd48959c5fb93eae273d67842c41a5b38823f04bb700000000000000000b05982ee8aa19d7a379a28705fb1ac8a168516f2372870793d1d8975b369151bd4953244fb3b9089aba368abacb02d96b62de1709fc3b680f40dbc9120caba54a7f3900a16c5f781a7dbfdb084f55bbca7814380e0e4f997fb66d320aee9867f0100000000000000b08df2e264b724af61ff2396751bc825f7884f29190ceeb79aa8acc4ca335a05ac5e29ba1ae7d95b6be273adacc596d000".as_bytes();
        let message = crate::chatter::Message::Output(crate::chatter::OutputMessage {
            payment_id: crate::bls::Scalar::from(18446744073709551615u64),
            output: output.to_vec(),
        });

        let s = match message.pack() {
            Ok(value) => value,
            Err(err) => {
                panic!("Cannot pack message {}", err);
            }
        };

        let mut buff = Cursor::new(Vec::new());
        crate::chatter::write_packet(&mut buff, s).unwrap();

        let encoded = hex::encode(&mut buff.get_mut());
        let expected = "01fdffffffffffffffff000000000000000000000000000000000000000000000000fdc402633030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030383130323066663662306663313833343961386237396535623430656636313161643034386634376135326666646331363439613065613333646436386138393437373630666330326635303430313037356161323536333933333165626630303261646236376337396363343064323134326633616632346334373365393966633164336239393961333334653837303235653966383038663636383562386235396137343031376337353462356462343461626662373463656666356135636562313564636161333932363364666431616139393631616638616364383337383461653633336662656161623262653233343866656464343839353963356662393365616532373364363738343263343161356233383832336630346262373030303030303030303030303030303030623035393832656538616131396437613337396132383730356662316163386131363835313666323337323837303739336431643839373562333639313531626434393533323434666233623930383961626133363861626163623032643936623632646531373039666333623638306634306462633931323063616261353461376633393030613136633566373831613764626664623038346635356262636137383134333830653065346639393766623636643332306165653938363766303130303030303030303030303030306230386466326532363462373234616636316666323339363735316263383235663738383466323931393063656562373961613861636334636133333561303561633565323962613161653764393562366265323733616461636335393664303030";
        assert_eq!(&encoded, &expected);
    }

    #[test]
    fn it_decodes_output_message() {
        let raw_message = "01fdffffffffffffffff000000000000000000000000000000000000000000000000fdc402633030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030383130323066663662306663313833343961386237396535623430656636313161643034386634376135326666646331363439613065613333646436386138393437373630666330326635303430313037356161323536333933333165626630303261646236376337396363343064323134326633616632346334373365393966633164336239393961333334653837303235653966383038663636383562386235396137343031376337353462356462343461626662373463656666356135636562313564636161333932363364666431616139393631616638616364383337383461653633336662656161623262653233343866656464343839353963356662393365616532373364363738343263343161356233383832336630346262373030303030303030303030303030303030623035393832656538616131396437613337396132383730356662316163386131363835313666323337323837303739336431643839373562333639313531626434393533323434666233623930383961626133363861626163623032643936623632646531373039666333623638306634306462633931323063616261353461376633393030613136633566373831613764626664623038346635356262636137383134333830653065346639393766623636643332306165653938363766303130303030303030303030303030306230386466326532363462373234616636316666323339363735316263383235663738383466323931393063656562373961613861636334636133333561303561633565323962613161653764393562366265323733616461636335393664303030";
        let message_bytes = hex::decode(raw_message).unwrap();
        let mut buffer = Cursor::new(message_bytes);
        let message = crate::chatter::read_packet(&mut buffer).unwrap();

        let expected_output_data = "c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000081020ff6b0fc18349a8b79e5b40ef611ad048f47a52ffdc1649a0ea33dd68a8947760fc02f50401075aa25639331ebf002adb67c79cc40d2142f3af24c473e99fc1d3b999a334e87025e9f808f6685b8b59a74017c754b5db44abfb74ceff5a5ceb15dcaa39263dfd1aa9961af8acd83784ae633fbeaab2be2348fedd48959c5fb93eae273d67842c41a5b38823f04bb700000000000000000b05982ee8aa19d7a379a28705fb1ac8a168516f2372870793d1d8975b369151bd4953244fb3b9089aba368abacb02d96b62de1709fc3b680f40dbc9120caba54a7f3900a16c5f781a7dbfdb084f55bbca7814380e0e4f997fb66d320aee9867f0100000000000000b08df2e264b724af61ff2396751bc825f7884f29190ceeb79aa8acc4ca335a05ac5e29ba1ae7d95b6be273adacc596d000".as_bytes();

        let mut payload = crate::chatter::Message::unpack(message).unwrap();
        if let crate::chatter::Message::Output(value) = payload {
            assert_eq!(expected_output_data.to_vec(), value.output);
        };
    }

    #[test]
    fn it_encodes_setup_output_message() {
        let blind_value = crate::bls::Scalar::from(18446744073709551615u64);
        let reply_addr = crate::bls::G1Projective::from_string(
            "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

        let message = crate::chatter::Message::SetupOutput(crate::chatter::SetupOutputMessage {
            payment_id: crate::bls::Scalar::from(18446744073709551615u64),
            blind_value: blind_value,
            reply_address: reply_addr,
        });

        let s = match message.pack() {
            Ok(value) => value,
            Err(err) => {
                panic!("Cannot pack message {}", err);
            }
        };

        let mut buff = Cursor::new(Vec::new());
        crate::chatter::write_packet(&mut buff, s).unwrap();

        let encoded = hex::encode(&mut buff.get_mut());
        let expected = "0270ffffffffffffffff000000000000000000000000000000000000000000000000ffffffffffffffff00000000000000000000000000000000000000000000000096ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7";
        assert_eq!(&encoded, &expected);
    }

    #[test]
    fn it_encode_setup_output_message() {
        let raw_message = "0270ffffffffffffffff0000000000000000000000000000000000000000000000000aa8d4b1f56e8dbbf40552494cd74cd90847f81f2d88613c18e88a8cddbbe92c96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7";
        let message_bytes = hex::decode(raw_message).unwrap();
        let mut buffer = Cursor::new(message_bytes);
        let message = crate::chatter::read_packet(&mut buffer).unwrap();

        let expected_reply_addr = crate::bls::G1Projective::from_string(
            "96ac67396e4d7998ca2328e8411ce3bf59c44832a70e6438dbede98adce3725a37c7fb7035213f934e112668d36235a7");

        let mut payload = crate::chatter::Message::unpack(message).unwrap();
        if let crate::chatter::Message::SetupOutput(value) = payload {
            assert_eq!(expected_reply_addr, value.reply_address);
        };
    }
}
<<<<<<< HEAD
*/
=======
>>>>>>> 4c096fe3c74d5277b00f0d79c6bf4471cf077a05
