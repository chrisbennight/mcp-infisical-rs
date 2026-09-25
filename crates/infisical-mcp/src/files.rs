//! The reveal transfer plane: secret values leave by reference, not in a tool result.
//!
//! A reveal-class operation that would place a secret value in model context can instead
//! stage a small JSON envelope here and return an opaque `mcp-file://infisical/…`
//! reference. A file-aware intermediary resolves that reference by calling
//! `files/authorizeDownload`, receives a descriptor naming this server's own download
//! route, and streams the envelope out-of-band. The value therefore reaches the caller's
//! host without ever appearing in a tool result, and so never in model context.
//!
//! Envelopes are held only in zeroizing memory — never on disk — because a secret is
//! kilobytes, not media. Every envelope is padded to a fixed-size bucket with a random
//! pad, so the size an intermediary publishes about the staged bytes is a coarse
//! deterministic bucket count and its content digest is salted: without the pad, a
//! published SHA-256 of a low-entropy password would be an offline-crackable oracle.
//!
//! The plane is deliberately instance-local. A staged reference resolves only on the
//! instance that minted it, and externalizing seconds-lived secret envelopes into shared
//! storage would trade that routing constraint for durable secret state.
//!
//! The plane is off unless an operator configures a public origin. Off means the
//! authorization method answers method-not-found, which a file-aware intermediary reads
//! as "no native file transfer", and reveal-class operations keep their inline behavior.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

#[path = "files/budget.rs"]
mod budget;
use budget::{ByteBudget, ByteReservation};

/// The MCP method a file-aware intermediary calls to obtain a download descriptor.
pub const AUTHORIZE_DOWNLOAD_METHOD: &str = "files/authorizeDownload";

/// Header the transfer credential travels in.
///
/// Deliberately not `Authorization`: the download route sits behind the same boundary as
/// `/mcp`, and a boundary that authenticates callers from `Authorization` would have
/// nowhere to put its own credential once this one claimed that header. A dedicated name
/// lets both travel on the same request, and a header rather than a URL component keeps
/// the credential out of proxy access logs.
pub const TRANSFER_CREDENTIAL_HEADER: &str = "Infisical-Transfer-Credential";

/// Scheme and authority this server mints for a staged envelope.
///
/// The `mcp-file` scheme is what a file-aware intermediary collects from a tool result;
/// the `infisical` authority distinguishes a reference this server minted from every
/// other server's. It is not a dereferenceable location and nothing treats it as one.
pub const STAGED_URI_PREFIX: &str = "mcp-file://infisical/";

/// Path prefix of the download route a descriptor names.
pub const DOWNLOAD_ROUTE_PREFIX: &str = "/files/download/";

/// The MCP method a file-aware intermediary calls to obtain an upload descriptor.
pub const AUTHORIZE_UPLOAD_METHOD: &str = "files/authorizeUpload";

/// Path prefix of the upload route a descriptor names.
pub const UPLOAD_ROUTE_PREFIX: &str = "/files/upload/";

/// Ceiling on one uploaded secret value. A secret is a value, not media; anything
/// larger than this is refused at authorization, before any bytes move.
pub const MAX_UPLOAD_BYTES: usize = 64 * 1024;

/// Maximum serialized envelope, including the random padding bucket.
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024 * 1024;

// JSON escaping takes at most six bytes per decoded byte. Credential outputs
// select material from one bounded response; typed PKI/SSH material is smaller.
// Two MiB additionally covers fixed wrappers and bounded identifiers/metadata.
const _: () =
    assert!(6 * infisical_api::MAXIMUM_RESPONSE_BYTES + 2 * 1024 * 1024 <= MAX_ENVELOPE_BYTES);

/// Media type of every staged envelope.
pub const ENVELOPE_MEDIA_TYPE: &str = "application/json";

/// Bytes of entropy in a staged identifier, a download identifier, and a credential.
///
/// The credential is the only authority on the download route and the staged reference is
/// the only authority to mint one, so both come from the platform CSPRNG.
const TOKEN_BYTES: usize = 32;

#[derive(Debug)]
pub enum FileError {
    /// No live staged envelope matches the reference or download identifier.
    UnknownReference,
    /// The presented transfer credential does not match the authorized one.
    BadCredential,
    /// The plane is at its staging ceiling.
    TooManyStaged { staged: usize },
    /// Promised or retained file bytes exhaust the configured aggregate budget.
    ByteCapacity,
    /// The declared upload size is over the per-value ceiling.
    UploadTooLarge { declared: u64 },
    /// The uploaded bytes do not match their declared size.
    SizeMismatch,
    /// The uploaded bytes do not match their declared digest.
    DigestMismatch,
    /// The declared digest algorithm is not SHA-256, or its value is malformed.
    UnsupportedDigest,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownReference => {
                formatter.write_str("no staged secret envelope matches that reference")
            }
            Self::BadCredential => {
                formatter.write_str("the transfer credential is not valid for this download")
            }
            Self::TooManyStaged { staged } => write!(
                formatter,
                "{staged} secret envelopes are already staged; download or let one expire first"
            ),
            Self::ByteCapacity => formatter.write_str(
                "file transfer byte capacity is reserved; finish a transfer or let a reference expire before trying again",
            ),
            Self::UploadTooLarge { declared } => write!(
                formatter,
                "declared size {declared} is over the {MAX_UPLOAD_BYTES}-byte upload ceiling"
            ),
            Self::SizeMismatch => {
                formatter.write_str("the upload did not carry its declared number of bytes")
            }
            Self::DigestMismatch => {
                formatter.write_str("the upload does not match its declared digest")
            }
            Self::UnsupportedDigest => {
                formatter.write_str("only base64url-encoded sha-256 digests are supported")
            }
        }
    }
}

impl FileError {
    /// Internal code for the operator's log.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownReference => "infisical_file_unknown_reference",
            Self::BadCredential => "infisical_file_bad_credential",
            Self::TooManyStaged { .. } => "infisical_file_too_many_staged",
            Self::ByteCapacity => "infisical_file_byte_capacity",
            Self::UploadTooLarge { .. } => "infisical_file_upload_too_large",
            Self::SizeMismatch => "infisical_file_size_mismatch",
            Self::DigestMismatch => "infisical_file_digest_mismatch",
            Self::UnsupportedDigest => "infisical_file_unsupported_digest",
        }
    }

    /// The code the download route puts on the wire.
    ///
    /// Every way of failing to present valid authority collapses to one value: a caller
    /// must not be able to tell a live download it guessed wrong from one that never
    /// existed, was already served, or expired — each distinct answer is an oracle for
    /// which identifiers are real.
    #[must_use]
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::UnknownReference | Self::BadCredential => "infisical_file_unauthorized",
            _ => self.code(),
        }
    }
}

/// The reference a reveal-class tool result carries in place of a secret value.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretFileReference {
    /// Opaque single-use reference resolved out-of-band; never a secret value.
    pub uri: String,
    /// Display name of the staged envelope.
    pub name: String,
    /// Media type of the staged envelope.
    pub mime_type: String,
}

/// Wire shape of one `files/authorizeDownload` result.
#[derive(Debug, Serialize)]
pub struct AuthorizeDownloadResult {
    pub file: SecretFileReference,
    /// Everything this plane stages is secret-class by design, so every result
    /// carries the fixed hint. A tolerant intermediary that understands it can
    /// shorten its own copy's retention; one that does not simply ignores an
    /// unknown member.
    pub sensitivity: &'static str,
    pub download: TransferDescriptor,
}

/// Params of `files/authorizeUpload`. Every field is optional in the draft; unknown
/// members, including `_meta`, are ignored.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeUploadParams {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub digest: Option<UploadDigest>,
}

/// A SEP-2631 digest: SHA-256 only, base64url without padding.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct UploadDigest {
    pub algorithm: String,
    pub value: String,
}

/// The file metadata an upload authorization echoes, exactly as declared: an
/// intermediary refuses a result that alters the metadata it just sent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EchoedFileValue {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<UploadDigest>,
}

/// Wire shape of one `files/authorizeUpload` result.
#[derive(Debug, Serialize)]
pub struct AuthorizeUploadResult {
    pub file: EchoedFileValue,
    pub upload: TransferDescriptor,
}

/// Where and how the intermediary fetches the staged envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferDescriptor {
    /// The scheme the URL actually uses. An intermediary that admits plaintext at all
    /// requires the two to agree, so a transfer cannot run in the clear under a
    /// descriptor claiming TLS.
    pub transport: &'static str,
    pub method: &'static str,
    pub url: String,
    /// Carries the transfer credential, the only authority on the download route.
    pub headers: HashMap<String, String>,
}

/// A staged envelope and, once authorized, the terms of its one download.
struct StagedSecret {
    envelope: TransferBytes,
    name: String,
    staged_at: Instant,
    download: Option<DownloadTicket>,
}

/// One authorized download. Re-authorizing replaces it, so at most one descriptor is
/// live per envelope and an old credential cannot outlast a newer authorization.
struct DownloadTicket {
    /// Appears in the descriptor URL and therefore in proxy logs; independent of the
    /// staged identifier, which must not be derivable from anything logged.
    id: String,
    credential_hash: [u8; 32],
}

/// How the transfer plane is configured. The plane exists only when an operator
/// configured a public origin.
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Origin the intermediary will dial, scheme and authority only, validated by the
    /// server's configuration layer before it reaches this type.
    pub public_origin: String,
    pub ttl: Duration,
    pub max_staged: usize,
    pub max_staged_bytes: usize,
}

/// A size-checked, zeroizing envelope produced by [`secret_envelope`].
pub struct SecretEnvelope {
    bytes: Zeroizing<Vec<u8>>,
}

impl std::ops::Deref for SecretEnvelope {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Download ownership retains the byte reservation until the transport drops it.
pub struct TransferBytes {
    bytes: Zeroizing<Vec<u8>>,
    _reservation: ByteReservation,
}

impl AsRef<[u8]> for TransferBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for TransferBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for TransferBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransferBytes([REDACTED])")
    }
}

/// Public delivery facts; excludes routing addresses, identifiers, and credentials.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileCapabilities {
    /// Server-owned extension identifier, not an MCP standard version.
    extension: &'static str,
    /// Revision of this server's file-transfer contract.
    version: u8,
    /// Maximum age in seconds before a staged value expires.
    ttl_seconds: f64,
    /// Combined ceiling for staged values and outstanding reservations.
    max_staged: usize,
    /// Aggregate promised and retained buffer capacity, including downloads in flight.
    max_staged_bytes: usize,
    /// Maximum serialized envelope, including its random padding.
    max_envelope_bytes: usize,
    /// Maximum bytes in a typed upload.
    max_upload_bytes: usize,
    /// References resolve only on the process that minted them.
    instance_local: bool,
    /// All staged values and transfer authorizations are lost on process restart.
    lost_on_restart: bool,
    /// Redemption consumes a transfer attempt; it does not acknowledge recipient receipt.
    redemption: &'static str,
}

/// One authorized upload: somewhere to put bytes and the terms they must meet.
struct UploadTicket {
    staged_id: String,
    credential_hash: [u8; 32],
    declared_size: Option<u64>,
    promised_bytes: usize,
    declared_digest: Option<[u8; 32]>,
    created_at: Instant,
    reservation: Option<ByteReservation>,
}

/// A completed upload, waiting to be named by a write-class tool call.
struct ReceivedSecret {
    bytes: TransferBytes,
    staged_at: Instant,
}

/// A claimed upload: the spent descriptor's terms, held while its body streams in.
///
/// Occupies one reserved slot until it completes or drops, so the ceiling keeps
/// bounding the transfer even though its ticket has left the map. Dropping without
/// completion — a transport error, an oversized body, a cancelled request — releases
/// the capacity and nothing else: the authorization was spent at claim time.
pub struct UploadClaim<'a> {
    plane: &'a SecretFilePlane,
    ticket: UploadTicket,
    released: bool,
}

impl UploadClaim<'_> {
    /// The promised body size; unknown-size uploads reserve the per-upload ceiling.
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.ticket.promised_bytes
    }

    /// Verify the streamed bytes against the claimed terms and hold them for the
    /// tool call that names them.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::SizeMismatch`] or [`FileError::DigestMismatch`]; the
    /// spent descriptor stays spent either way.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn complete(mut self, bytes: Zeroizing<Vec<u8>>) -> Result<(), FileError> {
        if bytes.len() > MAX_UPLOAD_BYTES || bytes.capacity() > self.ticket.promised_bytes {
            return Err(FileError::SizeMismatch);
        }
        if let Some(declared) = self.ticket.declared_size
            && bytes.len() as u64 != declared
        {
            return Err(FileError::SizeMismatch);
        }
        if let Some(expected) = self.ticket.declared_digest {
            let actual = sha256(&bytes);
            if aws_lc_rs::constant_time::verify_slices_are_equal(&actual, &expected).is_err() {
                return Err(FileError::DigestMismatch);
            }
        }
        let mut state = self.plane.state.lock().expect("transfer state lock");
        state.reserved = state.reserved.saturating_sub(1);
        self.released = true;
        let mut reservation = self
            .ticket
            .reservation
            .take()
            .expect("claimed upload reservation");
        // The HTTP receiver preallocates the promised length; spare capacity still
        // occupies memory after a short, unknown-length upload completes.
        reservation.shrink(bytes.capacity());
        state.received.insert(
            std::mem::take(&mut self.ticket.staged_id),
            ReceivedSecret {
                bytes: TransferBytes {
                    bytes,
                    _reservation: reservation,
                },
                staged_at: Instant::now(),
            },
        );
        Ok(())
    }
}

impl Drop for UploadClaim<'_> {
    fn drop(&mut self) {
        if !self.released
            && let Ok(mut state) = self.plane.state.lock()
        {
            state.reserved = state.reserved.saturating_sub(1);
        }
    }
}

/// Everything the plane counts against its ceiling, under one lock.
struct PlaneState {
    staged: HashMap<String, StagedSecret>,
    /// Slots promised to reveal calls that have not staged yet. Counted so a burst of
    /// concurrent reveals cannot all pass the ceiling, and so a reservation taken
    /// before the upstream call guarantees the later stage cannot be refused.
    reserved: usize,
    /// Authorized uploads whose bytes have not arrived. Counted so authorizations
    /// cannot multiply past the ceiling.
    uploads: HashMap<String, UploadTicket>,
    /// Uploaded values waiting for the tool call that names them.
    received: HashMap<String, ReceivedSecret>,
}

pub struct SecretFilePlane {
    config: FileConfig,
    state: Mutex<PlaneState>,
    byte_budget: Arc<ByteBudget>,
}

/// A promised staging slot, taken before the upstream operation runs.
///
/// One-time operations — token and client-secret creation, lease creation, certificate
/// issuance — return their credential exactly once. Refusing to stage after such an
/// operation completed would discard the only copy, so capacity is the reservation's
/// problem, not the stage's: [`SecretFilePlane::stage`] cannot fail once a slot exists.
/// Dropping an unused slot releases it, so a failed upstream call never leaks capacity.
pub struct StageSlot<'a> {
    plane: &'a SecretFilePlane,
    consumed: bool,
    reservation: Option<ByteReservation>,
}

impl StageSlot<'_> {
    /// Stage one envelope into this reserved slot. See [`SecretFilePlane::stage`].
    #[must_use]
    pub fn stage(self, operation: &str, envelope: SecretEnvelope) -> SecretFileReference {
        let plane = self.plane;
        plane.stage(self, operation, envelope)
    }

    fn release(&mut self) {
        if !self.consumed {
            self.consumed = true;
            let mut state = self.plane.state.lock().expect("transfer state lock");
            state.reserved = state.reserved.saturating_sub(1);
        }
    }
}

impl Drop for StageSlot<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Envelope sizes are quantized to this bucket, so the size a staging intermediary
/// publishes into model context is a coarse deterministic bucket count rather than a
/// function of the secret's length. A bounded random pad would not be enough: values
/// whose lengths differ by more than the pad range stay distinguishable, and repeated
/// reveals of one value would average the randomness away.
const ENVELOPE_BUCKET_BYTES: usize = 4096;

/// Minimum random characters in the pad, preserving its digest-salting job even when
/// the bucket is nearly full.
const MIN_PAD_CHARS: usize = 32;

/// Counts serialized bytes without retaining them, so the envelope can be measured
/// with no unzeroized copy of its contents.
struct CountingWriter(usize);

impl std::io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(buffer.len())
            .filter(|size| *size <= MAX_ENVELOPE_BYTES - MIN_PAD_CHARS)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "file envelope exceeds its byte limit",
                )
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Zeroize every string in the envelope tree before it is dropped, so the exposed
/// copies the tree was built from do not survive in freed allocator storage.
pub(crate) fn zeroize_tree(value: &mut Value) {
    use zeroize::Zeroize as _;
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_tree),
        Value::Object(map) => map.values_mut().for_each(zeroize_tree),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The envelope a reveal-class operation stages: the sensitive fields exactly as they
/// would have appeared inline, wrapped with the operation name and a pad.
///
/// The pad has random content and exactly the length that fills the envelope to the
/// next [`ENVELOPE_BUCKET_BYTES`] multiple. Random content salts the SHA-256 a staging
/// intermediary publishes into model context; the fixed bucket makes the published size
/// deterministic and independent of the value within a bucket, so repeated reveals leak
/// nothing an initial reveal did not.
///
/// The tree is measured through a counting writer, serialized exactly once into a
/// zeroizing buffer pre-sized so it never reallocates, and then zeroized itself, so no
/// copy of the material this function handles outlives it unzeroized.
///
/// # Errors
///
/// Returns an error if the padded envelope exceeds its byte limit or cannot be serialized.
pub fn secret_envelope(operation: &str, data: Value) -> Result<SecretEnvelope, serde_json::Error> {
    let mut envelope = serde_json::Map::new();
    envelope.insert("operation".to_owned(), Value::String(operation.to_owned()));
    envelope.insert("data".to_owned(), data);
    envelope.insert("pad".to_owned(), Value::String(String::new()));
    let mut tree = Value::Object(envelope);

    // Measure with an empty pad, then size the pad to the bucket boundary. The pad is
    // ASCII hex, so the final length is exactly the base length plus the fill.
    let mut counter = CountingWriter(0);
    if let Err(error) = serde_json::to_writer(&mut counter, &tree) {
        zeroize_tree(&mut tree);
        return Err(error);
    }
    let base = counter.0;
    let target = (base + MIN_PAD_CHARS).div_ceil(ENVELOPE_BUCKET_BYTES) * ENVELOPE_BUCKET_BYTES;
    if let Value::Object(envelope) = &mut tree {
        envelope.insert(
            "pad".to_owned(),
            Value::String(random_hex_of_length(target - base)),
        );
    }

    // Exactly one serialization, into a buffer with the final capacity: a zeroizing
    // buffer that grew would abandon its previous allocation without zeroizing it.
    let mut buffer = Zeroizing::new(Vec::with_capacity(target));
    let written = serde_json::to_writer(&mut *buffer, &tree);
    zeroize_tree(&mut tree);
    written?;
    debug_assert_eq!(buffer.len(), target, "the pad fills the bucket exactly");
    Ok(SecretEnvelope { bytes: buffer })
}

impl SecretFilePlane {
    pub(crate) fn capabilities(&self) -> FileCapabilities {
        FileCapabilities {
            extension: "io.cacahuate.infisical.file-transfer",
            version: 1,
            ttl_seconds: self.config.ttl.as_secs_f64(),
            max_staged: self.config.max_staged,
            max_staged_bytes: self.config.max_staged_bytes,
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            max_upload_bytes: MAX_UPLOAD_BYTES,
            instance_local: true,
            lost_on_restart: true,
            redemption: "atMostOneAttempt",
        }
    }

    #[must_use]
    pub fn new(config: FileConfig) -> Arc<Self> {
        let byte_budget = ByteBudget::new(config.max_staged_bytes);
        Arc::new(Self {
            config,
            byte_budget,
            state: Mutex::new(PlaneState {
                staged: HashMap::new(),
                reserved: 0,
                uploads: HashMap::new(),
                received: HashMap::new(),
            }),
        })
    }

    /// The transport a descriptor declares, taken from the validated origin. Anything
    /// that is not `https` is `http` by elimination.
    fn transport(&self) -> &'static str {
        if self.config.public_origin.starts_with("https://") {
            "https"
        } else {
            "http"
        }
    }

    /// Reserve one staging slot, before the upstream operation runs.
    ///
    /// Capacity is decided here, where nothing has happened yet, so a refusal costs the
    /// caller a retry rather than a one-time credential.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::TooManyStaged`] at the staging ceiling.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn reserve(&self) -> Result<StageSlot<'_>, FileError> {
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
        let outstanding = Self::outstanding(&state);
        if outstanding >= self.config.max_staged {
            return Err(FileError::TooManyStaged {
                staged: outstanding,
            });
        }
        let reservation = self
            .byte_budget
            .reserve(MAX_ENVELOPE_BYTES)
            .ok_or(FileError::ByteCapacity)?;
        state.reserved += 1;
        Ok(StageSlot {
            plane: self,
            consumed: false,
            reservation: Some(reservation),
        })
    }

    /// Stage one envelope into a reserved slot and mint the reference a tool result
    /// will carry. Infallible by design: the slot is the capacity decision, and this
    /// runs after an upstream operation that may have been one-shot.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn stage(
        &self,
        mut slot: StageSlot<'_>,
        operation: &str,
        envelope: SecretEnvelope,
    ) -> SecretFileReference {
        let id = random_token();
        let name = format!("{operation}.json");
        let reference = SecretFileReference {
            uri: format!("{STAGED_URI_PREFIX}{id}"),
            name: name.clone(),
            mime_type: ENVELOPE_MEDIA_TYPE.to_owned(),
        };
        {
            // The slot's count converts into the entry's count under one lock, so a
            // concurrent reservation always observes the ceiling as held.
            let mut state = self.state.lock().expect("transfer state lock");
            state.reserved = state.reserved.saturating_sub(1);
            slot.consumed = true;
            let mut reservation = slot.reservation.take().expect("reserved output bytes");
            reservation.shrink(envelope.len());
            state.staged.insert(
                id,
                StagedSecret {
                    envelope: TransferBytes {
                        bytes: envelope.bytes,
                        _reservation: reservation,
                    },
                    name,
                    staged_at: Instant::now(),
                    download: None,
                },
            );
        }
        reference
    }

    /// Mint a download descriptor for one staged reference.
    ///
    /// The returned file metadata repeats what the tool result declared, exactly: an
    /// intermediary refuses an authorization that alters the metadata it just saw.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::UnknownReference`] for anything that is not a live staged
    /// reference; expired and never-existed are deliberately indistinguishable.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn authorize_download(&self, uri: &str) -> Result<AuthorizeDownloadResult, FileError> {
        let id = uri
            .strip_prefix(STAGED_URI_PREFIX)
            .ok_or(FileError::UnknownReference)?;
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
        let entry = state
            .staged
            .get_mut(id)
            .ok_or(FileError::UnknownReference)?;

        // Two independent secrets: the download identifier travels in the descriptor URL
        // and therefore in ordinary access logs, so the credential that authorizes the
        // download must not be derivable from it, and neither may reveal the staged
        // reference. Only a hash of the credential is retained.
        let download_id = random_token();
        let credential = random_token();
        entry.download = Some(DownloadTicket {
            id: download_id.clone(),
            credential_hash: sha256(credential.as_bytes()),
        });

        let mut headers = HashMap::new();
        headers.insert(TRANSFER_CREDENTIAL_HEADER.to_owned(), credential);
        Ok(AuthorizeDownloadResult {
            file: SecretFileReference {
                uri: format!("{STAGED_URI_PREFIX}{id}"),
                name: entry.name.clone(),
                mime_type: ENVELOPE_MEDIA_TYPE.to_owned(),
            },
            sensitivity: "secret",
            download: TransferDescriptor {
                transport: self.transport(),
                method: "GET",
                url: format!(
                    "{}{DOWNLOAD_ROUTE_PREFIX}{download_id}",
                    self.config.public_origin
                ),
                headers,
            },
        })
    }

    /// Serve one authorized download and consume the envelope.
    ///
    /// Single-use: the envelope is removed once served, so a descriptor cannot be
    /// replayed to fetch the same secret twice. The credential comparison is constant
    /// time, and the entry survives a wrong credential so a guess cannot burn a live
    /// authorization.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::UnknownReference`] or [`FileError::BadCredential`]; the
    /// download route collapses both to one public refusal.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn serve(&self, download_id: &str, credential: &str) -> Result<TransferBytes, FileError> {
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
        let key = state
            .staged
            .iter()
            .find(|(_, entry)| {
                entry
                    .download
                    .as_ref()
                    .is_some_and(|ticket| ticket.id == download_id)
            })
            .map(|(key, _)| key.clone())
            .ok_or(FileError::UnknownReference)?;

        let ticket = state.staged[&key]
            .download
            .as_ref()
            .expect("matched on a present ticket");
        let presented = sha256(credential.as_bytes());
        if aws_lc_rs::constant_time::verify_slices_are_equal(&presented, &ticket.credential_hash)
            .is_err()
        {
            return Err(FileError::BadCredential);
        }

        let entry = state.staged.remove(&key).expect("matched under this lock");
        Ok(entry.envelope)
    }

    /// Mint a single-use authorization for one secret upload.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::TooManyStaged`] at the ceiling,
    /// [`FileError::UploadTooLarge`] for a declared size over the per-value bound, and
    /// [`FileError::UnsupportedDigest`] for a digest that is not base64url SHA-256.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn authorize_upload(
        &self,
        params: AuthorizeUploadParams,
    ) -> Result<AuthorizeUploadResult, FileError> {
        if let Some(declared) = params.size
            && declared > MAX_UPLOAD_BYTES as u64
        {
            return Err(FileError::UploadTooLarge { declared });
        }
        let declared_digest = match &params.digest {
            None => None,
            Some(digest) => {
                if !digest.algorithm.eq_ignore_ascii_case("sha-256") {
                    return Err(FileError::UnsupportedDigest);
                }
                Some(decode_digest(&digest.value)?)
            }
        };

        // Three independent secrets, as on the download side: the upload identifier
        // travels in the descriptor URL and therefore in access logs, so neither the
        // credential nor the reference a tool call later redeems may be derivable
        // from it.
        let upload_id = random_token();
        let staged_id = random_token();
        let credential = random_token();

        {
            let mut state = self.state.lock().expect("transfer state lock");
            Self::sweep_locked(&mut state, self.config.ttl);
            let outstanding = Self::outstanding(&state);
            if outstanding >= self.config.max_staged {
                return Err(FileError::TooManyStaged {
                    staged: outstanding,
                });
            }
            let promised_bytes = match params.size {
                Some(size) => usize::try_from(size)
                    .map_err(|_| FileError::UploadTooLarge { declared: size })?,
                None => MAX_UPLOAD_BYTES,
            };
            let reservation = self
                .byte_budget
                .reserve(promised_bytes)
                .ok_or(FileError::ByteCapacity)?;
            state.uploads.insert(
                upload_id.clone(),
                UploadTicket {
                    staged_id: staged_id.clone(),
                    credential_hash: sha256(credential.as_bytes()),
                    declared_size: params.size,
                    promised_bytes,
                    declared_digest,
                    created_at: Instant::now(),
                    reservation: Some(reservation),
                },
            );
        }

        let mut headers = HashMap::new();
        headers.insert(TRANSFER_CREDENTIAL_HEADER.to_owned(), credential);
        Ok(AuthorizeUploadResult {
            file: EchoedFileValue {
                uri: format!("{STAGED_URI_PREFIX}{staged_id}"),
                name: params.name,
                mime_type: params.mime_type,
                size: params.size,
                digest: params.digest,
            },
            upload: TransferDescriptor {
                transport: self.transport(),
                method: "PUT",
                url: format!(
                    "{}{UPLOAD_ROUTE_PREFIX}{upload_id}",
                    self.config.public_origin
                ),
                headers,
            },
        })
    }

    /// Claim one upload authorization, verifying the credential before consuming it.
    ///
    /// The credential check and the consumption happen under one lock: a wrong
    /// credential leaves the ticket live, so a guess cannot burn an authorization,
    /// while a valid claim spends the descriptor immediately. Every later outcome —
    /// completion, a mismatched body, a transport error, or cancellation — is
    /// therefore an already-spent attempt, structurally: the claim owns the terms and
    /// its drop releases only the capacity, never the authorization. This runs before
    /// any request-body byte is read, so an unauthenticated peer costs nothing beyond
    /// this check.
    ///
    /// # Errors
    ///
    /// Returns [`FileError::UnknownReference`] or [`FileError::BadCredential`].
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn claim_upload(
        &self,
        upload_id: &str,
        credential: &str,
    ) -> Result<UploadClaim<'_>, FileError> {
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
        let ticket = state
            .uploads
            .get(upload_id)
            .ok_or(FileError::UnknownReference)?;
        let presented = sha256(credential.as_bytes());
        if aws_lc_rs::constant_time::verify_slices_are_equal(&presented, &ticket.credential_hash)
            .is_err()
        {
            return Err(FileError::BadCredential);
        }

        // The ticket leaves the map and its slot moves to the reserved count under the
        // same lock, so a concurrent authorization always observes the ceiling as held
        // while the transfer runs.
        let ticket = state
            .uploads
            .remove(upload_id)
            .expect("present under this lock");
        state.reserved += 1;
        Ok(UploadClaim {
            plane: self,
            ticket,
            released: false,
        })
    }

    /// Consume one uploaded value by the reference this server minted for it.
    ///
    /// Single-use, and `None` for anything that is not a live uploaded reference:
    /// expired and never-existed are deliberately indistinguishable.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn take_received(&self, uri: &str) -> Option<Zeroizing<Vec<u8>>> {
        let id = uri.strip_prefix(STAGED_URI_PREFIX)?;
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
        state.received.remove(id).map(|entry| entry.bytes.bytes)
    }

    /// Drop envelopes that outlived their window, zeroizing their bytes.
    ///
    /// Expiry is also enforced at every entry point, so this exists to reclaim memory
    /// on a schedule rather than to enforce the window.
    ///
    /// # Panics
    ///
    /// Panics if the transfer state lock is poisoned.
    pub fn sweep(&self) {
        let mut state = self.state.lock().expect("transfer state lock");
        Self::sweep_locked(&mut state, self.config.ttl);
    }

    fn sweep_locked(state: &mut PlaneState, ttl: Duration) {
        state
            .staged
            .retain(|_, entry| entry.staged_at.elapsed() <= ttl);
        state
            .uploads
            .retain(|_, ticket| ticket.created_at.elapsed() <= ttl);
        state
            .received
            .retain(|_, entry| entry.staged_at.elapsed() <= ttl);
    }

    fn outstanding(state: &PlaneState) -> usize {
        state.staged.len() + state.reserved + state.uploads.len() + state.received.len()
    }

    #[cfg(test)]
    fn staged_count(&self) -> usize {
        self.state.lock().expect("transfer state lock").staged.len()
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    aws_lc_rs::rand::fill(&mut bytes).expect("platform CSPRNG");
    hex(&bytes)
}

/// Random hex content of exactly the requested length.
fn random_hex_of_length(length: usize) -> String {
    let mut bytes = vec![0u8; length.div_ceil(2)];
    aws_lc_rs::rand::fill(&mut bytes).expect("platform CSPRNG");
    let mut out = hex(&bytes);
    out.truncate(length);
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn decode_digest(value: &str) -> Result<[u8; 32], FileError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|raw| raw.try_into().ok())
        .ok_or(FileError::UnsupportedDigest)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane(ttl: Duration, max_staged: usize) -> Arc<SecretFilePlane> {
        plane_with_budget(ttl, max_staged, max_staged * MAX_ENVELOPE_BYTES)
    }

    fn plane_with_budget(
        ttl: Duration,
        max_staged: usize,
        max_staged_bytes: usize,
    ) -> Arc<SecretFilePlane> {
        SecretFilePlane::new(FileConfig {
            public_origin: "http://infisical-mcp:8000".to_owned(),
            ttl,
            max_staged,
            max_staged_bytes,
        })
    }

    #[test]
    fn maximum_upstream_string_fits_even_with_worst_case_json_escaping() {
        let material = "\u{0001}".repeat(infisical_api::MAXIMUM_RESPONSE_BYTES);
        let envelope = secret_envelope(
            "identityTokenAuth.tokens.create",
            serde_json::json!({
                "accessToken": material,
            }),
        )
        .unwrap();
        assert!(envelope.len() > 6 * infisical_api::MAXIMUM_RESPONSE_BYTES);
        assert!(envelope.len() <= MAX_ENVELOPE_BYTES);
        assert_eq!(envelope.len() % ENVELOPE_BUCKET_BYTES, 0);
    }

    #[test]
    fn envelope_measurement_rejects_the_first_byte_above_its_limit() {
        use std::io::Write;
        let mut counter = CountingWriter(MAX_ENVELOPE_BYTES - MIN_PAD_CHARS - 1);
        assert_eq!(counter.write(b"x").unwrap(), 1);
        assert!(counter.write(b"y").is_err());
    }

    #[test]
    fn output_bytes_are_promised_before_staging_and_released_on_cancellation() {
        let plane = plane_with_budget(Duration::from_mins(1), 4, 2 * MAX_ENVELOPE_BYTES - 1);
        let first = plane.reserve().unwrap();
        assert!(matches!(plane.reserve(), Err(FileError::ByteCapacity)));
        drop(first);
        assert!(plane.reserve().is_ok());
    }

    #[test]
    fn downloaded_bytes_stay_charged_until_the_transport_owner_drops() {
        let plane = plane_with_budget(
            Duration::from_mins(1),
            4,
            MAX_ENVELOPE_BYTES + ENVELOPE_BUCKET_BYTES,
        );
        let reference = stage(&plane, "held-in-transport");
        let authorized = plane.authorize_download(&reference.uri).unwrap();
        let body = plane
            .serve(download_id_of(&authorized), credential_of(&authorized))
            .unwrap();
        assert_eq!(body.len(), ENVELOPE_BUCKET_BYTES);
        assert_eq!(plane.staged_count(), 0);
        let pending = plane.reserve().unwrap();
        let one_byte = || AuthorizeUploadParams {
            size: Some(1),
            ..Default::default()
        };
        assert!(matches!(
            plane.authorize_upload(one_byte()),
            Err(FileError::ByteCapacity)
        ));
        assert!(!format!("{body:?}").contains("held-in-transport"));
        drop(body);
        assert!(plane.authorize_upload(one_byte()).is_ok());
        drop(pending);
    }

    #[test]
    fn claimed_upload_bytes_survive_map_removal_and_failures_release_them() {
        let plane = plane_with_budget(Duration::from_mins(1), 4, 8);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams {
                size: Some(8),
                ..Default::default()
            })
            .unwrap();
        let (id, credential) = upload_descriptor_ids(&authorized);
        let claim = plane.claim_upload(id, credential).unwrap();
        assert_eq!(claim.max_bytes(), 8);
        assert!(matches!(
            plane.authorize_upload(AuthorizeUploadParams {
                size: Some(1),
                ..Default::default()
            }),
            Err(FileError::ByteCapacity)
        ));
        assert!(matches!(
            claim.complete(Zeroizing::new(vec![0; 7])),
            Err(FileError::SizeMismatch)
        ));
        assert!(matches!(
            plane.claim_upload(id, credential),
            Err(FileError::UnknownReference)
        ));
        assert!(
            plane
                .authorize_upload(AuthorizeUploadParams {
                    size: Some(8),
                    ..Default::default()
                })
                .is_ok()
        );
    }

    #[test]
    fn short_upload_keeps_its_allocated_capacity_charged_until_consumed() {
        let plane = plane_with_budget(Duration::from_mins(1), 4, MAX_UPLOAD_BYTES);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams::default())
            .unwrap();
        let (id, credential) = upload_descriptor_ids(&authorized);
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_UPLOAD_BYTES));
        bytes.push(0);
        plane
            .claim_upload(id, credential)
            .unwrap()
            .complete(bytes)
            .unwrap();
        assert!(matches!(
            plane.authorize_upload(AuthorizeUploadParams {
                size: Some(1),
                ..Default::default()
            }),
            Err(FileError::ByteCapacity)
        ));
        drop(plane.take_received(&authorized.file.uri).unwrap());
        assert!(
            plane
                .authorize_upload(AuthorizeUploadParams::default())
                .is_ok()
        );
    }

    #[test]
    fn unknown_upload_size_reserves_the_full_ceiling_until_completion() {
        let plane = plane_with_budget(Duration::from_mins(1), 4, MAX_UPLOAD_BYTES);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams::default())
            .unwrap();
        assert!(matches!(
            plane.authorize_upload(AuthorizeUploadParams {
                size: Some(1),
                ..Default::default()
            }),
            Err(FileError::ByteCapacity)
        ));
        let (id, credential) = upload_descriptor_ids(&authorized);
        plane
            .claim_upload(id, credential)
            .unwrap()
            .complete(Zeroizing::new(vec![0; 1]))
            .unwrap();
        assert!(
            plane
                .authorize_upload(AuthorizeUploadParams {
                    size: Some((MAX_UPLOAD_BYTES - 1) as u64),
                    ..Default::default()
                })
                .is_ok()
        );
        assert!(plane.take_received(&authorized.file.uri).is_some());
        assert!(
            plane
                .authorize_upload(AuthorizeUploadParams {
                    size: Some(1),
                    ..Default::default()
                })
                .is_ok()
        );
    }

    #[test]
    fn expiry_reclaims_uploaded_bytes_and_restart_does_not_restore_a_reference() {
        let plane = plane_with_budget(Duration::from_mins(1), 4, 8);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams {
                size: Some(8),
                ..Default::default()
            })
            .unwrap();
        let (id, credential) = upload_descriptor_ids(&authorized);
        plane
            .claim_upload(id, credential)
            .unwrap()
            .complete(Zeroizing::new(vec![0; 8]))
            .unwrap();
        for entry in plane.state.lock().unwrap().received.values_mut() {
            entry.staged_at = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap();
        }
        plane.sweep();
        assert!(plane.take_received(&authorized.file.uri).is_none());
        assert!(
            plane
                .authorize_upload(AuthorizeUploadParams {
                    size: Some(8),
                    ..Default::default()
                })
                .is_ok()
        );
        let restarted = plane_with_budget(Duration::from_mins(1), 4, 8);
        assert!(restarted.take_received(&authorized.file.uri).is_none());
    }

    fn envelope(canary: &str) -> SecretEnvelope {
        secret_envelope(
            "secrets.reveal",
            serde_json::json!({ "secretValue": canary }),
        )
        .expect("serialize envelope")
    }

    fn stage(plane: &SecretFilePlane, canary: &str) -> SecretFileReference {
        plane.stage(
            plane.reserve().expect("reserve a slot"),
            "secrets.reveal",
            envelope(canary),
        )
    }

    fn credential_of(result: &AuthorizeDownloadResult) -> &str {
        result
            .download
            .headers
            .get(TRANSFER_CREDENTIAL_HEADER)
            .expect("descriptor carries the credential")
    }

    fn download_id_of(result: &AuthorizeDownloadResult) -> &str {
        result
            .download
            .url
            .rsplit('/')
            .next()
            .expect("descriptor URL ends in the download identifier")
    }

    #[test]
    fn a_staged_envelope_downloads_exactly_once() {
        let plane = plane(Duration::from_mins(1), 4);
        let reference = stage(&plane, "canary-roundtrip");
        assert!(reference.uri.starts_with(STAGED_URI_PREFIX));
        assert_eq!(reference.name, "secrets.reveal.json");

        let authorized = plane.authorize_download(&reference.uri).expect("authorize");
        assert_eq!(authorized.file.uri, reference.uri);
        assert_eq!(authorized.download.method, "GET");
        assert_eq!(authorized.download.transport, "http");
        assert!(
            authorized
                .download
                .url
                .starts_with("http://infisical-mcp:8000/files/download/")
        );

        let body = plane
            .serve(download_id_of(&authorized), credential_of(&authorized))
            .expect("serve");
        let parsed: Value = serde_json::from_slice(body.as_ref()).expect("envelope is JSON");
        assert_eq!(parsed["operation"], "secrets.reveal");
        assert_eq!(parsed["data"]["secretValue"], "canary-roundtrip");
        assert!(parsed["pad"].as_str().is_some_and(|pad| !pad.is_empty()));

        assert!(matches!(
            plane.serve(download_id_of(&authorized), credential_of(&authorized)),
            Err(FileError::UnknownReference)
        ));
    }

    #[test]
    fn a_wrong_credential_is_refused_without_burning_the_download() {
        let plane = plane(Duration::from_mins(1), 4);
        let reference = stage(&plane, "canary");
        let authorized = plane.authorize_download(&reference.uri).expect("authorize");

        assert!(matches!(
            plane.serve(download_id_of(&authorized), "not-the-credential"),
            Err(FileError::BadCredential)
        ));
        plane
            .serve(download_id_of(&authorized), credential_of(&authorized))
            .expect("the true credential still serves after a wrong guess");
    }

    #[test]
    fn nothing_serves_without_an_authorization() {
        let plane = plane(Duration::from_mins(1), 4);
        let reference = stage(&plane, "canary");
        let staged_id = reference
            .uri
            .strip_prefix(STAGED_URI_PREFIX)
            .expect("minted prefix");
        assert!(matches!(
            plane.serve(staged_id, "anything"),
            Err(FileError::UnknownReference)
        ));
    }

    #[test]
    fn reauthorizing_replaces_the_previous_descriptor() {
        let plane = plane(Duration::from_mins(1), 4);
        let reference = stage(&plane, "canary");
        let first = plane.authorize_download(&reference.uri).expect("authorize");
        let second = plane
            .authorize_download(&reference.uri)
            .expect("reauthorize");

        assert!(matches!(
            plane.serve(download_id_of(&first), credential_of(&first)),
            Err(FileError::UnknownReference)
        ));
        plane
            .serve(download_id_of(&second), credential_of(&second))
            .expect("the newest descriptor serves");
    }

    #[test]
    fn the_staging_ceiling_holds_over_reservations_and_entries() {
        let plane = plane(Duration::from_mins(1), 2);
        stage(&plane, "one");
        let held = plane
            .reserve()
            .expect("a reservation takes the second slot");
        assert!(matches!(
            plane.reserve(),
            Err(FileError::TooManyStaged { staged: 2 })
        ));
        drop(held);
        plane
            .reserve()
            .expect("dropping an unused reservation releases its slot");
    }

    #[test]
    fn a_reserved_slot_makes_staging_infallible_at_the_ceiling() {
        let plane = plane(Duration::from_mins(1), 1);
        let slot = plane.reserve().expect("reserve the only slot");
        // The upstream operation would run here; nothing can take the slot away.
        let reference = plane.stage(slot, "secrets.reveal", envelope("kept"));
        assert!(reference.uri.starts_with(STAGED_URI_PREFIX));
        assert_eq!(plane.staged_count(), 1);
    }

    #[test]
    fn expiry_applies_at_every_entry_point() {
        let plane = plane(Duration::from_millis(1), 4);
        let reference = stage(&plane, "canary");
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            plane.authorize_download(&reference.uri),
            Err(FileError::UnknownReference)
        ));
        assert_eq!(
            plane.staged_count(),
            0,
            "the expired envelope was reclaimed"
        );
    }

    #[test]
    fn the_sweeper_reclaims_expired_envelopes() {
        let plane = plane(Duration::from_millis(1), 4);
        stage(&plane, "canary");
        std::thread::sleep(Duration::from_millis(20));
        plane.sweep();
        assert_eq!(plane.staged_count(), 0);
    }

    #[test]
    fn envelopes_of_identical_data_differ() {
        let first = envelope("same-value");
        let second = envelope("same-value");
        assert_ne!(
            &*first, &*second,
            "the random pad decorrelates envelope bytes from the secret value"
        );
    }

    #[test]
    fn envelope_sizes_are_bucketed_and_deterministic() {
        let short = envelope("s");
        let longer = envelope(&"x".repeat(600));
        assert_eq!(short.len() % ENVELOPE_BUCKET_BYTES, 0);
        assert_eq!(longer.len() % ENVELOPE_BUCKET_BYTES, 0);
        assert_eq!(
            short.len(),
            longer.len(),
            "values within one bucket serialize to identical sizes"
        );
        assert_eq!(
            envelope("s").len(),
            envelope("s").len(),
            "repeated reveals of one value expose no average to converge on"
        );
    }

    fn upload_descriptor_ids(result: &AuthorizeUploadResult) -> (&str, &str) {
        let upload_id = result
            .upload
            .url
            .rsplit('/')
            .next()
            .expect("descriptor URL ends in the upload identifier");
        let credential = result
            .upload
            .headers
            .get(TRANSFER_CREDENTIAL_HEADER)
            .expect("descriptor carries the credential");
        (upload_id, credential)
    }

    fn digest_of(bytes: &[u8]) -> UploadDigest {
        use base64::Engine as _;
        UploadDigest {
            algorithm: "sha-256".to_owned(),
            value: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(bytes)),
        }
    }

    #[test]
    fn an_authorized_upload_stages_a_value_exactly_once() {
        let plane = plane(Duration::from_mins(1), 4);
        let value = b"uploaded-secret-canary";
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams {
                name: Some("STRIPE_API_KEY".into()),
                mime_type: Some("text/plain".into()),
                size: Some(value.len() as u64),
                digest: Some(digest_of(value)),
            })
            .expect("authorize upload");
        assert!(authorized.file.uri.starts_with(STAGED_URI_PREFIX));
        assert_eq!(authorized.upload.method, "PUT");
        assert!(
            authorized
                .upload
                .url
                .starts_with("http://infisical-mcp:8000/files/upload/")
        );

        let (upload_id, credential) = upload_descriptor_ids(&authorized);
        plane
            .claim_upload(upload_id, credential)
            .expect("claim upload")
            .complete(Zeroizing::new(value.to_vec()))
            .expect("complete upload");

        let taken = plane
            .take_received(&authorized.file.uri)
            .expect("the uploaded value resolves");
        assert_eq!(taken.as_slice(), value);
        assert!(
            plane.take_received(&authorized.file.uri).is_none(),
            "an uploaded value resolves exactly once"
        );
    }

    #[test]
    fn a_wrong_upload_credential_is_refused_without_burning_the_ticket() {
        let plane = plane(Duration::from_mins(1), 4);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams::default())
            .expect("authorize upload");
        let (upload_id, credential) = upload_descriptor_ids(&authorized);

        assert!(matches!(
            plane.claim_upload("unknown", credential),
            Err(FileError::UnknownReference)
        ));
        assert!(matches!(
            plane.claim_upload(upload_id, "not-the-credential"),
            Err(FileError::BadCredential)
        ));
        plane
            .claim_upload(upload_id, credential)
            .expect("the true credential still claims after a wrong guess")
            .complete(Zeroizing::new(b"v".to_vec()))
            .expect("complete upload");
    }

    #[test]
    fn an_abandoned_claim_spends_the_descriptor_and_releases_its_slot() {
        let plane = plane(Duration::from_mins(1), 1);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams::default())
            .expect("authorize upload");
        let (upload_id, credential) = upload_descriptor_ids(&authorized);

        // A transport failure mid-body drops the claim without completing it.
        drop(plane.claim_upload(upload_id, credential).expect("claim"));

        assert!(
            matches!(
                plane.claim_upload(upload_id, credential),
                Err(FileError::UnknownReference)
            ),
            "an attempted transfer spends the single-use descriptor"
        );
        plane
            .reserve()
            .expect("the abandoned claim released its capacity slot");
    }

    #[test]
    fn an_upload_that_breaks_its_declaration_is_refused_and_spent() {
        let plane = plane(Duration::from_mins(1), 4);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams {
                size: Some(5),
                digest: Some(digest_of(b"right")),
                ..AuthorizeUploadParams::default()
            })
            .expect("authorize upload");
        let (upload_id, credential) = upload_descriptor_ids(&authorized);

        assert!(matches!(
            plane
                .claim_upload(upload_id, credential)
                .expect("claim")
                .complete(Zeroizing::new(b"wrong-size".to_vec())),
            Err(FileError::SizeMismatch)
        ));
        // The transfer was attempted with valid authority, so the descriptor is spent.
        assert!(matches!(
            plane.claim_upload(upload_id, credential),
            Err(FileError::UnknownReference)
        ));
    }

    #[test]
    fn an_upload_with_the_wrong_digest_is_refused() {
        let plane = plane(Duration::from_mins(1), 4);
        let authorized = plane
            .authorize_upload(AuthorizeUploadParams {
                digest: Some(digest_of(b"declared")),
                ..AuthorizeUploadParams::default()
            })
            .expect("authorize upload");
        let (upload_id, credential) = upload_descriptor_ids(&authorized);
        assert!(matches!(
            plane
                .claim_upload(upload_id, credential)
                .expect("claim")
                .complete(Zeroizing::new(b"different".to_vec())),
            Err(FileError::DigestMismatch)
        ));
    }

    #[test]
    fn upload_authorizations_count_against_the_ceiling() {
        let plane = plane(Duration::from_mins(1), 1);
        plane
            .authorize_upload(AuthorizeUploadParams::default())
            .expect("first authorization");
        assert!(matches!(
            plane.authorize_upload(AuthorizeUploadParams::default()),
            Err(FileError::TooManyStaged { staged: 1 })
        ));
        assert!(matches!(
            plane.reserve(),
            Err(FileError::TooManyStaged { staged: 1 })
        ));
    }

    #[test]
    fn an_oversized_upload_declaration_is_refused_at_authorization() {
        let plane = plane(Duration::from_mins(1), 4);
        assert!(matches!(
            plane.authorize_upload(AuthorizeUploadParams {
                size: Some(MAX_UPLOAD_BYTES as u64 + 1),
                ..AuthorizeUploadParams::default()
            }),
            Err(FileError::UploadTooLarge { .. })
        ));
    }

    #[test]
    fn a_foreign_uri_is_not_authorized() {
        let plane = plane(Duration::from_mins(1), 4);
        assert!(matches!(
            plane.authorize_download("mcp-file://gateway/not-ours"),
            Err(FileError::UnknownReference)
        ));
    }
}
