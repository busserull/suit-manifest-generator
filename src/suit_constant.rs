use crate::Cbor;

pub const SUIT_ENVELOPE_TAG: u64 = 107;

pub enum SuitConstant {
    AuthenticationWrapper,
    Manifest,

    CoseAlgSha256,
    CoseAlgShake128,
    CoseAlgSha384,
    CoseAlgSha512,
    CoseAlgShake256,

    ManifestVersion,
    ManifestSequenceNumber,
    Common,
    Components,
    CommonSequence,
    ReferenceUri,
    PayloadFetch,
    Install,
    Validate,
    Load,
    Run,
    Text,

    ConditionVendorIdentifier,
    ConditionClassIdentifier,
    ConditionImageMatch,
    ConditionComponentSlot,
    ConditionAbort,
    ConditionDeviceIdentifier,

    DirectiveSetComponentIndex,
    DirectiveTryEach,
    DirectiveOverrideParameters,
    DirectiveFetch,
    DirectiveCopy,
    DirectiveRun,
    DirectiveSwap,
    DirectiveRunSequence,

    ParameterVendorIdentifier,
    ParameterClassIdentifier,
    ParameterImageDigest,
    ParameterComponentSlot,
    ParameterStrictOrder,
    ParameterSoftFailure,
    ParameterImageSize,
    ParameterUri,
    ParameterSourceComponent,
    ParameterRunArgs,
    ParameterDeviceIdentifier,

    TextManifestDescription,
    TextUpdateDescription,
    TextManifestJsonSource,
    TextManifestYamlSource,
    TextVendorName,
    TextModelName,
    TextVendorDomain,
    TextModelInfo,
    TextComponentDescription,
    TextComponentVersion,
}

impl From<SuitConstant> for Cbor {
    fn from(suit_constant: SuitConstant) -> Self {
        use Cbor::{Nint, Uint};
        use SuitConstant::*;

        match suit_constant {
            AuthenticationWrapper => Uint(2),
            Manifest => Uint(3),

            CoseAlgSha256 => Nint(16),
            CoseAlgShake128 => Nint(18),
            CoseAlgSha384 => Nint(43),
            CoseAlgSha512 => Nint(44),
            CoseAlgShake256 => Nint(45),

            ManifestVersion => Uint(1),
            ManifestSequenceNumber => Uint(2),
            Common => Uint(3),
            Components => Uint(2),
            CommonSequence => Uint(4),
            ReferenceUri => Uint(4),
            PayloadFetch => Uint(8),
            Install => Uint(9),
            Validate => Uint(10),
            Load => Uint(11),
            Run => Uint(12),
            Text => Uint(13),

            ConditionVendorIdentifier => Uint(1),
            ConditionClassIdentifier => Uint(2),
            ConditionImageMatch => Uint(3),
            ConditionComponentSlot => Uint(5),
            ConditionAbort => Uint(14),
            ConditionDeviceIdentifier => Uint(24),

            DirectiveSetComponentIndex => Uint(12),
            DirectiveTryEach => Uint(15),
            DirectiveOverrideParameters => Uint(20),
            DirectiveFetch => Uint(21),
            DirectiveCopy => Uint(22),
            DirectiveRun => Uint(23),
            DirectiveSwap => Uint(31),
            DirectiveRunSequence => Uint(32),

            ParameterVendorIdentifier => Uint(1),
            ParameterClassIdentifier => Uint(2),
            ParameterImageDigest => Uint(3),
            ParameterComponentSlot => Uint(5),
            ParameterStrictOrder => Uint(12),
            ParameterSoftFailure => Uint(13),
            ParameterImageSize => Uint(14),
            ParameterUri => Uint(21),
            ParameterSourceComponent => Uint(22),
            ParameterRunArgs => Uint(23),
            ParameterDeviceIdentifier => Uint(24),

            TextManifestDescription => Uint(1),
            TextUpdateDescription => Uint(2),
            TextManifestJsonSource => Uint(3),
            TextManifestYamlSource => Uint(4),
            TextVendorName => Uint(1),
            TextModelName => Uint(2),
            TextVendorDomain => Uint(3),
            TextModelInfo => Uint(4),
            TextComponentDescription => Uint(5),
            TextComponentVersion => Uint(6),
        }
    }
}
