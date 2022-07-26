//! Representation for firmware upgrade payloads.

use std::collections::hash_map::HashMap;
use std::path::PathBuf;

mod compression;

const PAYLOAD_SPLIT_PENALTY: u32 = 4;

/// Representation of a SUIT payload.
#[derive(Debug)]
pub struct Payload {
    /// URI of the payload. The custom URI schemes "p:" and "cp:"
    /// are used to denote raw payloads and compressed payloads, respectively.
    pub uri: String,

    /// The start address of the payload location.
    pub start_address: u32,

    /// The size of the payload in bytes.
    pub size: usize,

    /// The raw bytes of the payload.
    pub bytes: Vec<u8>,
}

/// Create a list of SUIT Payloads from a list of all hex files that
/// constitute a device firmware update.
pub fn from_hex_files(
    files: &[PathBuf],
    fill_value: u8,
    allow_overwrites: bool,
    use_compression: bool,
) -> Vec<Payload> {
    let mut raw_content: HashMap<u32, (u8, &PathBuf)> = HashMap::new();

    for file in files {
        let file_content = read_hex(file);

        for (address, byte) in file_content {
            if !allow_overwrites && raw_content.contains_key(&address) {
                let (original_byte, original_file) = raw_content[&address];
                panic!(
                    "the value at address `{:#04x}` is set multiple times; \
                        first by `{:?}` ({:#02x}), and then by `{:?}` ({:#02x})",
                    address, original_file, original_byte, file, byte
                );
            }

            raw_content.insert(address, (byte, file));
        }
    }

    let mut linear_memory: Vec<(u32, u8)> = raw_content
        .into_iter()
        .map(|(address, (byte, _path))| (address, byte))
        .collect();

    linear_memory.sort_unstable();

    let gaps = find_gaps(&linear_memory);

    let gap_offsets = gaps
        .iter()
        .filter(|(_offset, gap)| *gap >= PAYLOAD_SPLIT_PENALTY)
        .map(|(offset, _gap)| offset);

    let mut chunks = vec![0];
    chunks.extend(gap_offsets);
    chunks.push(linear_memory.len());

    let segments: Vec<(u32, Vec<u8>)> = chunks
        .windows(2)
        .map(|window| {
            let start = window[0];
            let end = window[1];

            normalize_memory(&linear_memory[start..end], fill_value)
        })
        .collect();

    let model = compression::default_model::model();

    segments
        .iter()
        .enumerate()
        .map(|(index, (address, raw_bytes))| {
            let uri = match use_compression {
                true => format!("cp:{}", index),
                false => format!("p:{}", index),
            };

            let bytes = match use_compression {
                true => compression::encode(&model, &raw_bytes),
                false => raw_bytes.to_vec(),
            };

            let size = bytes.len();

            Payload {
                uri,
                start_address: *address,
                size,
                bytes,
            }
        })
        .collect()
}

/// Record type for the Intel Hex format.
enum HexRecord {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    ExtendedLinearAddress,
}

impl From<u8> for HexRecord {
    fn from(byte: u8) -> Self {
        use HexRecord::*;

        match byte {
            0 => Data,
            1 => EndOfFile,
            2 => ExtendedSegmentAddress,
            4 => ExtendedLinearAddress,
            _ => panic!("Unsupported Hex record type `{}`", byte),
        }
    }
}

/// Read a file in Intel Hex format, returning it as a vector of
/// addresses with their corresponding byte values.
fn read_hex(file: &PathBuf) -> Vec<(u32, u8)> {
    let hex_content = std::fs::read_to_string(file)
        .unwrap_or_else(|_| panic!("could not read file `{:?}`", file));

    let mut result = Vec::new();

    let mut extended_segment_address = 0;
    let mut extended_linear_address = 0;

    for line in hex_content.lines() {
        let bytes = hex::decode(&line[1..]).unwrap_or_else(|_| {
            panic!(
                "could not parse hex content in line `{}`, file `{:?}`",
                line, file
            )
        });
        let length = bytes.len();

        let computed_checksum = (&bytes[0..length - 1]
            .iter()
            .fold(0u8, |acc, &x| acc.wrapping_add(x))
            ^ 0xff)
            .wrapping_add(1u8);

        let included_checksum = bytes[length - 1];

        assert_eq!(
            included_checksum, computed_checksum,
            "checksum mismatch {:#02x} vs. expected {:#02x} in line `{}`, file `{:?}`",
            included_checksum, computed_checksum, line, file
        );

        let count = bytes[0] as usize;
        let base_address = (bytes[1] as u32) << 8 | bytes[2] as u32;
        let record_type: HexRecord = bytes[3].into();
        let bytes = &bytes[length - count - 1..length - 1];

        match record_type {
            HexRecord::Data => {
                for (offset, byte) in bytes.iter().enumerate() {
                    result.push((
                        (extended_linear_address << 16)
                            | (16 * extended_segment_address + base_address + (offset as u32)),
                        *byte,
                    ));
                }
            }
            HexRecord::EndOfFile => break,
            HexRecord::ExtendedSegmentAddress => {
                assert_eq!(count, 2, "Incorrect extended segment address length");
                extended_segment_address = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
            }
            HexRecord::ExtendedLinearAddress => {
                assert_eq!(count, 2, "Incorrect extended linear address length");
                extended_linear_address = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
            }
        }
    }

    result
}

/// Find the locations of gaps in the content of a hex file. Gaps are jumps
/// in address locations where the bytes in between are not explicitly set.
/// The input to this function must be sorted.
fn find_gaps(hex_content: &[(u32, u8)]) -> Vec<(usize, u32)> {
    let first_address = match hex_content.first() {
        None => 0,
        Some((address, _byte)) => *address,
    };

    hex_content
        .iter()
        .map(|(address, _byte)| address)
        .enumerate()
        .fold(
            (first_address, Vec::new()),
            |(last_address, mut acc), (index, &address)| {
                let gap = address - last_address;

                if gap > 1 {
                    acc.push((index, gap));
                }

                (address, acc)
            },
        )
        .1
}

/// Normalize the memory content of a hex file, filling in gap values with a
/// specified fill byte value.
/// The input to this function must be sorted.
fn normalize_memory(hex_content: &[(u32, u8)], fill_value: u8) -> (u32, Vec<u8>) {
    let first_address = match hex_content.first() {
        None => 0,
        Some((address, _byte)) => *address,
    };

    let bytes = hex_content
        .iter()
        .fold(
            (first_address, Vec::new()),
            |(last_address, mut acc), &(address, byte)| {
                let mut fill = match address - last_address {
                    0 | 1 => Vec::new(),
                    gap_size => vec![fill_value; gap_size as usize],
                };

                acc.append(&mut fill);
                acc.push(byte);

                (address, acc)
            },
        )
        .1;

    (first_address, bytes)
}
