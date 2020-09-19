use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Foo,
    CommitsDontAdd,
    InvalidCredential,
    TransactionPedersenCheckFailed,
    TokenAlreadySpent,
    InputTokenVerifyFailed,
    RangeproofPedersenMatchFailed,
    ProofsFailed,
    MissingProofs,
    Io(std::io::Error),
    /// VarInt was encoded in a non-minimal way
    NonMinimalVarInt,
    /// Parsing error
    ParseFailed(&'static str),
    AsyncChannelError,
    MalformedPacket,
    AddrParseError,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Foo => f.write_str("foo"),
            Error::CommitsDontAdd => f.write_str("Commits don't add up properly"),
            Error::InvalidCredential => f.write_str("Credential is invalid"),
            Error::TransactionPedersenCheckFailed => {
                f.write_str("Transaction pedersens for input and output don't sum up")
            }
            Error::TokenAlreadySpent => f.write_str("This input token is already spent"),
            Error::InputTokenVerifyFailed => f.write_str("Input token verify of credential failed"),
            Error::RangeproofPedersenMatchFailed => {
                f.write_str("Rangeproof pedersen check for match failed")
            }
            Error::ProofsFailed => f.write_str("Proof validation failed"),
            Error::MissingProofs => f.write_str("Missing proofs"),
            Error::Io(ref err) => fmt::Display::fmt(err, f),
            Error::NonMinimalVarInt => f.write_str("non-minimal varint"),
            Error::ParseFailed(ref err) => write!(f, "parse failed: {}", err),
            Error::AsyncChannelError => f.write_str("async_channel error"),
            Error::MalformedPacket => f.write_str("Malformed packet"),
            Error::AddrParseError => f.write_str("Unable to parse address"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl<T> From<async_channel::SendError<T>> for Error {
    fn from(_err: async_channel::SendError<T>) -> Error {
        Error::AsyncChannelError
    }
}

impl From<async_channel::RecvError> for Error {
    fn from(_err: async_channel::RecvError) -> Error {
        Error::AsyncChannelError
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(_err: std::net::AddrParseError) -> Error {
        Error::AddrParseError
    }
}
