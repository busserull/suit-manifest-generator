#[derive(Clone, Debug)]
pub enum Cbor {
    Uint(u64),
    Nint(u64),
    Bstr(Vec<u8>),
    Tstr(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    True,
    False,
    Null,
}

impl Cbor {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Cbor::Uint(number) => encode_header(0, *number),
            Cbor::Nint(number) => {
                if *number == 0 {
                    encode_header(0, *number)
                } else {
                    encode_header(1, *number - 1)
                }
            }
            Cbor::Bstr(bytes) => {
                let mut encoded = encode_header(2, bytes.len() as u64);
                encoded.extend(bytes);

                encoded
            }
            Cbor::Tstr(string) => {
                let bytes = string.as_bytes();
                let mut encoded = encode_header(3, bytes.len() as u64);
                encoded.extend(bytes);

                encoded
            }
            Cbor::Array(elements) => {
                let encoded = encode_header(4, elements.len() as u64);
                elements.iter().fold(encoded, |mut acc, x| {
                    acc.extend(x.serialize());
                    acc
                })
            }
            Cbor::Map(elements) => {
                let encoded = encode_header(5, elements.len() as u64);
                elements.iter().fold(encoded, |mut acc, (k, v)| {
                    acc.extend(k.serialize());
                    acc.extend(v.serialize());
                    acc
                })
            }
            Cbor::Tag(number, tagged_element) => {
                let mut encoded = encode_header(6, *number);
                encoded.extend(tagged_element.serialize());

                encoded
            }
            Cbor::True => encode_header(7, 21),
            Cbor::False => encode_header(7, 20),
            Cbor::Null => encode_header(7, 22),
        }
    }
}

impl From<Vec<u8>> for Cbor {
    fn from(bytes: Vec<u8>) -> Cbor {
        Cbor::Bstr(bytes)
    }
}

impl From<String> for Cbor {
    fn from(text: String) -> Cbor {
        Cbor::Tstr(text)
    }
}

impl From<u64> for Cbor {
    fn from(number: u64) -> Cbor {
        Cbor::Uint(number)
    }
}

impl From<bool> for Cbor {
    fn from(boolean: bool) -> Cbor {
        if boolean {
            Cbor::True
        } else {
            Cbor::False
        }
    }
}

fn encode_header(major_type: u8, argument: u64) -> Vec<u8> {
    if argument < 24 {
        return vec![major_type << 5 | argument as u8];
    }

    let bytes = argument.to_be_bytes();

    let used = 8 - bytes.iter().position(|&byte| byte != 0).unwrap();

    let (argument_in, argument_extended) = match used {
        1 => (24, Vec::from(&bytes[7..8])),
        2 => (25, Vec::from(&bytes[6..8])),
        3 | 4 => (26, Vec::from(&bytes[4..8])),
        _ => (27, Vec::from(bytes)),
    };

    let mut encoded = vec![major_type << 5 | argument_in];
    encoded.extend(argument_extended);

    encoded
}
