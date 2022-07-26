//! Facilities for performing entropy coding compression based on
//! Asymmetric Numeral Systems; a novel approach to entropy coding
//! that combines the compression of arithmetic coding with the
//! efficiency of Huffman coding.
//!
//! The following is an implementation of rANS, outlined in:
//! * Asymmetric numeral systems, Jarek Duda, 2009
//! * A tutorial on the range variant of asymmetric
//!   numeral systems, James Townsend, 2020
//!
//! The probabilities used in the models for encoding and decoding
//! are represented as unsigned integer weights, and may be
//! quantized with a specified number of bits.

use std::collections::HashMap;
use std::hash::Hash;
use std::iter::Iterator;

pub mod default_model;

/// Encode a `stream` of symbols with probabilities approximated
/// be a `model`.
///
/// # Panics
///
/// This function will panic if the input stream contains symbols
/// that do not exist in the model.
///
/// # Examples
///
/// ```
/// let model = Model::<char>::new(3, &[('a', 2), ('b', 3), ('c', 3)]);
///
/// let input = ['a', 'a', 'c', 'b', 'c', 'b', 'c'];
///
/// let encoding = encode(&model, &input);
/// ```
///
pub fn encode<'a, T>(model: &'a Model<T>, stream: &[T]) -> Vec<u8>
where
    T: Copy + Eq + Hash,
{
    let mut encoder = Coder::new(model);

    for symbol in stream.iter().rev() {
        encoder.push(*symbol);
    }

    encoder.bytes()
}

/// Decode a `stream` of bytes, based on a probability `model`.
///
/// # Panics
///
/// This function will panic if the input stream is malformed.
/// That is, if no valid terminating bytes are included in the stream.
///
/// # Examples
///
/// ```
/// let model = Model::<char>::new(3, &[('a', 2), ('b', 3), ('c', 3)]);
///
/// let encoding = [75, 218, 19, 0, 178];
///
/// let decoding = decode(&model, &encoding);
/// ```
pub fn decode<'a, T>(model: &'a Model<T>, stream: &[u8]) -> Vec<T>
where
    T: Copy + Eq + Hash,
{
    let decoder = Coder::from_bytes(model, stream);
    decoder.into_iter().collect()
}

/// Model representing the probability that a certain set of symbols
/// will appear in some stream of symbols.
pub struct Model<T>
where
    T: Copy + Eq + Hash,
{
    symbols: HashMap<T, (u32, u32)>,
    cumulative_probability: Vec<(u32, T)>,
    precision: u32,
}

impl<T> Model<T>
where
    T: Copy + Eq + Hash,
{
    /// Create a model with probability quantization level `precision` bits.
    /// A quantization level of e.g. 3 approximates probabilities in steps of 8,
    /// as `exp(2, 3) = 8`.
    ///
    /// The sum of all weighted probabilities in `quantized_symbols` must sum
    /// to the total amount of quantization steps. I.e. 8 for `precision` of 3.
    ///
    /// # Panics
    ///
    /// Panics if `precision` is either 0 bits, or more than 32 bits.
    ///
    /// Panics if the cumulative probabilities of all possible symbols in the
    /// model does not sum to the total probability space.
    ///
    /// # Examples
    /// ```
    /// // Possible symbols are 'a', 'b', 'c', and 'd'.
    /// // Probabilities are quantized at 1/8, 2/8, 3/8, and 2/8, respectively.
    /// // The quantization level is 3 bits.
    ///
    /// let symbols = [('a', 1), ('b', 2), ('c', 3), ('d', 2)];
    ///
    /// let model = Model::<char>::new(3, &symbols);
    /// ```
    pub fn new(precision: u32, quantized_symbols: &[(T, u32)]) -> Self {
        assert!(
            precision > 0,
            "Quantized probability precision must be larger than 0 bits"
        );

        let (expected_total, overflow) = 1_u32.overflowing_shl(precision);

        assert!(!overflow, "Quantized probability precision too large");

        let total_probability = quantized_symbols
            .iter()
            .map(|(_symbol, probability)| *probability)
            .reduce(|acc, p| acc + p)
            .expect("No symbols given in model");

        assert_eq!(
            expected_total, total_probability,
            "Quantized probabilities must sum to 2 raised to the precision"
        );

        let cumulative_probability: Vec<(u32, T)> = quantized_symbols
            .iter()
            .fold(vec![0], |mut acc, (_symbol, probability)| {
                acc.push(acc.last().unwrap() + probability);
                acc
            })
            .into_iter()
            .zip(
                quantized_symbols
                    .iter()
                    .map(|(symbol, _probability)| symbol)
                    .copied(),
            )
            .collect();

        let symbols: HashMap<T, (u32, u32)> = quantized_symbols
            .iter()
            .zip(cumulative_probability.iter())
            .map(|((symbol, probability), (cumulated, _symbol))| {
                (*symbol, (*probability, *cumulated))
            })
            .collect();

        Self {
            symbols,
            cumulative_probability,
            precision,
        }
    }

    fn get_probability(&self, symbol: T) -> (u32, u32) {
        self.symbols.get(&symbol).copied().unwrap()
    }

    fn get_symbol(&self, prediction: u32) -> (T, u32, u32) {
        let symbol = self
            .cumulative_probability
            .iter()
            .rfind(|(cumulated, _symbol)| prediction >= *cumulated)
            .unwrap()
            .1;

        let (probability, cumulated) = self.get_probability(symbol);

        (symbol, probability, cumulated)
    }
}

struct Coder<'a, T>
where
    T: Copy + Eq + Hash,
{
    stack: Vec<u8>,
    segment: u32,
    model: &'a Model<T>,
    empty_message: u32,
}

impl<'a, T> Coder<'a, T>
where
    T: Copy + Eq + Hash,
{
    fn new(model: &'a Model<T>) -> Self {
        let empty_message = 1 << (32 - 8);

        Self {
            stack: Vec::new(),
            segment: empty_message,
            model,
            empty_message,
        }
    }

    fn from_bytes(model: &'a Model<T>, bytes: &[u8]) -> Self {
        let mut stack: Vec<u8> = bytes.iter().rev().copied().collect();
        let mut segment = 0;

        while segment < (1 << (32 - 8)) {
            segment <<= 8;
            segment |= stack.pop().expect("Not enough input bytes") as u32;
        }

        // Potential for improvement:
        // Check that end of message is included somewhere,
        // and return a result Err(...) if it is not

        Self {
            stack,
            segment,
            model,
            empty_message: 1 << (32 - 8),
        }
    }

    fn push(&mut self, symbol: T) {
        let (p, c) = self.model.get_probability(symbol);
        let mut s = self.segment;

        while s >= p << (32 - self.model.precision) {
            self.stack.push(s as u8);
            s = s.wrapping_shr(8);
        }

        self.segment = ((s / p) << self.model.precision) + (s % p) + c;
    }

    fn pop(&mut self) -> Option<T> {
        if self.segment == self.empty_message {
            return None;
        }

        let prediction = self.segment & ((1 << self.model.precision) - 1);
        let (symbol, p, c) = self.model.get_symbol(prediction);

        let mut s = p * (self.segment >> self.model.precision) + prediction - c;

        while s < (1 << (32 - 8)) {
            s <<= 8;
            s |= self
                .stack
                .pop()
                .expect("Byte stream incorrectly terminated") as u32;
        }

        self.segment = s;

        Some(symbol)
    }

    fn bytes(&self) -> Vec<u8> {
        self.segment
            .to_be_bytes()
            .iter()
            .chain(self.stack.iter().rev())
            .copied()
            .collect()
    }
}

impl<'a, T> Iterator for Coder<'a, T>
where
    T: Copy + Eq + Hash,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.pop()
    }
}
