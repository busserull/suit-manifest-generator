use std::path::PathBuf;

use clap::{Parser, ValueEnum};

mod cbor;
mod payload;
mod suit_constant;

use cbor::Cbor;
use payload::Payload;
use suit_constant::SuitConstant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Payload list to use in manifest
    #[clap(value_parser = cli_legal_hex_file)]
    payload: Vec<PathBuf>,

    /// Allow that subsequent payloads overwrite earlier ones without error
    #[clap(short, long, value_parser, default_value_t = false)]
    allow_overwrites: bool,

    /// Manifest sequence number
    #[clap(short, long, value_parser, default_value_t = 0)]
    sequence_number: u64,

    /// Use payload compression
    #[clap(short, long, value_parser, default_value_t = true)]
    compress: bool,

    /// The value that an unwritten byte has in memory
    #[clap(short, long, value_parser, default_value_t = 0xff)]
    fill: u8,

    /// Algorithm to create payload digests with
    #[clap(short, long, value_parser, default_value = "sha256")]
    digest_algorithm: DigestAlgorithm,
}

fn cli_legal_hex_file(arg: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(arg);

    let extension = path
        .extension()
        .ok_or(String::from("Unknown file type; no extension specified"))?;

    match extension.to_str().unwrap() {
        "hex" => Ok(path),
        file_type => Err(format!("Unsupported file format `{}`", file_type)),
    }
}

fn main() {
    let args = Cli::parse();

    let payloads = payload::from_hex_files(
        &args.payload,
        args.fill,
        args.allow_overwrites,
        args.compress,
    );

    let components: Vec<ComponentIdentifier> = payloads
        .iter()
        .map(|payload| ComponentIdentifier(payload.start_address))
        .collect();

    let common = Common {
        components,
        common_sequence: None,
    };

    let validate = payloads
        .iter()
        .enumerate()
        .map(|(component_index, payload)| {
            vec![
                Command::DirectiveSetComponentIndex(IndexArgument::Single(component_index)),
                Command::DirectiveOverrideParameters(vec![
                    Parameter::ImageDigest(args.digest_algorithm.apply(&payload.bytes)),
                    Parameter::ImageSize(payload.size),
                ]),
                Command::ConditionImageMatch(ReportingPolicy::all()),
            ]
        })
        .reduce(|mut acc, mut sequence| {
            acc.append(&mut sequence);
            acc
        });

    let load = payloads
        .iter()
        .enumerate()
        .map(|(component_index, payload)| {
            vec![
                Command::DirectiveSetComponentIndex(IndexArgument::Single(component_index)),
                Command::DirectiveOverrideParameters(vec![Parameter::Uri(payload.uri.clone())]),
                Command::DirectiveFetch(ReportingPolicy::all()),
            ]
        })
        .reduce(|mut acc, mut sequence| {
            acc.append(&mut sequence);
            acc
        });

    let run = Some(vec![
        Command::DirectiveSetComponentIndex(IndexArgument::Single(0)),
        Command::DirectiveRun(ReportingPolicy::none()),
    ]);

    let manifest = Manifest {
        sequence_number: args.sequence_number,
        reference_uri: None,

        common,

        validate,
        load,
        run,

        payload_fetch: None,
        install: None,
        text: None,
    };

    let envelope = Envelope {
        authentication_wrapper: Authentication {},
        manifest,
        integrated_payloads: payloads,
        add_tag: true,
    };

    let cbor = Cbor::from(envelope);

    let serialized = cbor.serialize();

    println!("{:#?}", cbor);
    println!("{:?}", serialized);
}

#[derive(Debug)]
struct Envelope {
    authentication_wrapper: Authentication,
    manifest: Manifest,
    integrated_payloads: Vec<Payload>,

    add_tag: bool,
}

impl From<Envelope> for Cbor {
    fn from(envelope: Envelope) -> Self {
        let payloads = envelope
            .integrated_payloads
            .into_iter()
            .map(|payload| (payload.uri.into(), payload.bytes.into()));

        let mut envelope_content = vec![
            (
                SuitConstant::AuthenticationWrapper.into(),
                envelope.authentication_wrapper.into(),
            ),
            (SuitConstant::Manifest.into(), envelope.manifest.into()),
        ];

        envelope_content.extend(payloads);

        let untagged_envelope = Cbor::Map(envelope_content);

        if envelope.add_tag {
            Cbor::Tag(
                suit_constant::SUIT_ENVELOPE_TAG,
                Box::new(untagged_envelope),
            )
        } else {
            untagged_envelope
        }
    }
}

#[derive(Debug)]
struct Authentication {}

impl From<Authentication> for Cbor {
    fn from(authentication: Authentication) -> Self {
        Cbor::Uint(1)
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

impl DigestAlgorithm {
    fn apply(&self, input: &[u8]) -> Digest {
        use openssl::hash::{hash, MessageDigest};
        use DigestAlgorithm::*;

        let hasher = match self {
            Sha256 => MessageDigest::sha256(),
            Sha384 => MessageDigest::sha384(),
            Sha512 => MessageDigest::sha512(),
            Shake128 => MessageDigest::shake_128(),
            Shake256 => MessageDigest::shake_256(),
        };

        Digest {
            algorithm: *self,
            bytes: hash(hasher, input).unwrap().to_vec(),
        }
    }
}

impl From<DigestAlgorithm> for Cbor {
    fn from(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha256 => SuitConstant::CoseAlgSha256.into(),
            DigestAlgorithm::Shake128 => SuitConstant::CoseAlgShake128.into(),
            DigestAlgorithm::Sha384 => SuitConstant::CoseAlgSha384.into(),
            DigestAlgorithm::Sha512 => SuitConstant::CoseAlgSha512.into(),
            DigestAlgorithm::Shake256 => SuitConstant::CoseAlgShake256.into(),
        }
    }
}

#[derive(Debug)]
struct Digest {
    algorithm: DigestAlgorithm,
    bytes: Vec<u8>,
}

impl From<Digest> for Cbor {
    fn from(digest: Digest) -> Cbor {
        Cbor::Array(vec![digest.algorithm.into(), digest.bytes.into()])
    }
}

#[derive(Debug)]
struct Manifest {
    sequence_number: u64,
    reference_uri: Option<String>,

    common: Common,

    validate: Option<Vec<Command>>,
    load: Option<Vec<Command>>,
    run: Option<Vec<Command>>,

    payload_fetch: Option<Vec<Command>>,
    install: Option<Vec<Command>>,
    text: Option<Vec<Command>>,
}

impl From<Manifest> for Cbor {
    fn from(manifest: Manifest) -> Cbor {
        let components = Cbor::Array(
            manifest
                .common
                .components
                .into_iter()
                .map(|component| component.into())
                .collect(),
        );

        let mut common_content = vec![(SuitConstant::Components.into(), components)];

        if let Some(commands) = manifest.common.common_sequence {
            let sequence = commands
                .into_iter()
                .map(|command| command.into_cbor_pair())
                .fold(Vec::new(), |mut acc, pair| {
                    acc.push(pair.0);
                    acc.push(pair.1);
                    acc
                });

            common_content.push((SuitConstant::CommonSequence.into(), Cbor::Array(sequence)));
        }

        let common = Cbor::Map(common_content);

        let head = vec![
            (SuitConstant::ManifestVersion.into(), 1.into()),
            (
                SuitConstant::ManifestSequenceNumber.into(),
                (manifest.sequence_number).into(),
            ),
            (SuitConstant::Common.into(), common),
        ];

        let reference_uri = match manifest.reference_uri {
            Some(uri) => vec![(SuitConstant::ReferenceUri.into(), uri.into())],
            None => Vec::new(),
        };

        let command_sequences = [
            (SuitConstant::PayloadFetch, manifest.payload_fetch),
            (SuitConstant::Install, manifest.install),
            (SuitConstant::Text, manifest.text),
            (SuitConstant::Validate, manifest.validate),
            (SuitConstant::Load, manifest.load),
            (SuitConstant::Run, manifest.run),
        ]
        .into_iter()
        .filter(|(_key, value)| value.is_some())
        .map(|(key, value)| (key.into(), value.unwrap().into()));

        Cbor::Map(
            head.into_iter()
                .chain(reference_uri.into_iter())
                .chain(command_sequences)
                .collect(),
        )
    }
}

#[derive(Debug)]
struct Common {
    components: Vec<ComponentIdentifier>,
    common_sequence: Option<Vec<Command>>,
}

impl From<Common> for Cbor {
    fn from(common: Common) -> Cbor {
        let identifiers = common
            .components
            .into_iter()
            .map(|component| component.into())
            .collect();
        let components = (SuitConstant::Components.into(), Cbor::Array(identifiers));

        match common.common_sequence {
            Some(sequence) => Cbor::Map(vec![
                components,
                (SuitConstant::CommonSequence.into(), sequence.into()),
            ]),
            None => Cbor::Map(vec![components]),
        }
    }
}

#[derive(Debug)]
struct ComponentIdentifier(u32);

impl From<u32> for ComponentIdentifier {
    fn from(address: u32) -> Self {
        Self(address)
    }
}

impl From<ComponentIdentifier> for Cbor {
    fn from(component: ComponentIdentifier) -> Cbor {
        Cbor::Array(vec![component.0.to_be_bytes().to_vec().into()])
    }
}

#[derive(Debug)]
enum Command {
    ConditionVendorIdentifier(ReportingPolicy),
    ConditionClassIdentifier(ReportingPolicy),
    ConditionDeviceIdentifier(ReportingPolicy),
    ConditionImageMatch(ReportingPolicy),
    ConditionComponentSlot(ReportingPolicy),
    ConditionAbort(ReportingPolicy),

    DirectiveSetComponentIndex(IndexArgument),
    // DirectiveRunSequence,
    // DirectiveTryEach,
    // DirectiveProcessDependency(ReportingPolicy),
    DirectiveOverrideParameters(Vec<Parameter>),
    DirectiveFetch(ReportingPolicy),
    DirectiveCopy(ReportingPolicy),
    DirectiveSwap(ReportingPolicy),
    DirectiveRun(ReportingPolicy),
}

impl Command {
    fn into_cbor_pair(self) -> (Cbor, Cbor) {
        match self {
            Command::ConditionVendorIdentifier(policy) => (
                SuitConstant::ConditionVendorIdentifier.into(),
                policy.into(),
            ),
            Command::ConditionClassIdentifier(policy) => {
                (SuitConstant::ConditionClassIdentifier.into(), policy.into())
            }
            Command::ConditionDeviceIdentifier(policy) => (
                SuitConstant::ConditionDeviceIdentifier.into(),
                policy.into(),
            ),
            Command::ConditionImageMatch(policy) => {
                (SuitConstant::ConditionImageMatch.into(), policy.into())
            }
            Command::ConditionComponentSlot(policy) => {
                (SuitConstant::ConditionComponentSlot.into(), policy.into())
            }
            Command::ConditionAbort(policy) => (SuitConstant::ConditionAbort.into(), policy.into()),

            Command::DirectiveSetComponentIndex(index) => (
                SuitConstant::DirectiveSetComponentIndex.into(),
                index.into(),
            ),
            Command::DirectiveOverrideParameters(parameters) => (
                SuitConstant::DirectiveOverrideParameters.into(),
                parameters.into(),
            ),
            Command::DirectiveFetch(policy) => (SuitConstant::DirectiveFetch.into(), policy.into()),
            Command::DirectiveCopy(policy) => (SuitConstant::DirectiveCopy.into(), policy.into()),
            Command::DirectiveSwap(policy) => (SuitConstant::DirectiveSwap.into(), policy.into()),
            Command::DirectiveRun(policy) => (SuitConstant::DirectiveRun.into(), policy.into()),
        }
    }
}

impl From<Vec<Command>> for Cbor {
    fn from(sequence: Vec<Command>) -> Cbor {
        Cbor::Array(sequence.into_iter().fold(Vec::new(), |mut acc, x| {
            let (key, value) = x.into_cbor_pair();
            acc.push(key);
            acc.push(value);
            acc
        }))
    }
}

#[derive(Debug)]
enum Parameter {
    // ClassIdentifier(RFC4122_UUID),
    ImageDigest(Digest),
    ImageSize(usize),
    ComponentSlot(usize),
    Uri(String),
    SourceComponent(usize),
    RunArgs(Vec<u8>),
    // DeviceIdentifier(RFC4122_UUID),
    StrictOrder(bool),
    SoftFailure(bool),
}

impl Parameter {
    fn into_cbor_pair(self) -> (Cbor, Cbor) {
        match self {
            Parameter::ImageDigest(digest) => {
                (SuitConstant::ParameterImageDigest.into(), digest.into())
            }
            Parameter::ImageSize(size) => (
                SuitConstant::ParameterImageSize.into(),
                (size as u64).into(),
            ),
            Parameter::ComponentSlot(slot) => (
                SuitConstant::ParameterComponentSlot.into(),
                (slot as u64).into(),
            ),
            Parameter::Uri(uri) => (SuitConstant::ParameterUri.into(), uri.into()),
            Parameter::SourceComponent(source) => (
                SuitConstant::ParameterSourceComponent.into(),
                (source as u64).into(),
            ),
            Parameter::RunArgs(arguments) => {
                (SuitConstant::ParameterRunArgs.into(), arguments.into())
            }
            Parameter::StrictOrder(flag) => {
                (SuitConstant::ParameterStrictOrder.into(), flag.into())
            }
            Parameter::SoftFailure(flag) => {
                (SuitConstant::ParameterSoftFailure.into(), flag.into())
            }
        }
    }
}

impl From<Vec<Parameter>> for Cbor {
    fn from(parameters: Vec<Parameter>) -> Cbor {
        Cbor::Map(
            parameters
                .into_iter()
                .map(|parameter| parameter.into_cbor_pair())
                .collect(),
        )
    }
}

#[derive(Debug)]
struct ReportingPolicy {
    record_success: bool,
    record_failure: bool,
    sysinfo_success: bool,
    sysinfo_failure: bool,
}

impl ReportingPolicy {
    fn all() -> Self {
        Self {
            record_success: true,
            record_failure: true,
            sysinfo_success: true,
            sysinfo_failure: true,
        }
    }

    fn none() -> Self {
        Self {
            record_success: false,
            record_failure: false,
            sysinfo_success: false,
            sysinfo_failure: false,
        }
    }
}

impl From<ReportingPolicy> for Cbor {
    fn from(policy: ReportingPolicy) -> Cbor {
        Cbor::Uint(
            (policy.record_success as u64)
                | ((policy.record_failure as u64) << 1)
                | ((policy.sysinfo_success as u64) << 2)
                | ((policy.sysinfo_failure as u64) << 3),
        )
    }
}

#[derive(Debug)]
enum IndexArgument {
    Single(usize),
    All,
    List(Vec<usize>),
}

impl From<IndexArgument> for Cbor {
    fn from(index: IndexArgument) -> Cbor {
        match index {
            IndexArgument::Single(index) => Cbor::Uint(index as u64),
            IndexArgument::All => Cbor::True,
            IndexArgument::List(indices) => Cbor::Array(
                indices
                    .into_iter()
                    .map(|index| Cbor::Uint(index as u64))
                    .collect(),
            ),
        }
    }
}
