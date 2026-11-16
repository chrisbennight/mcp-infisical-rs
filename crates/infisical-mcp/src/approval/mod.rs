//! Process-local human approval, independent of transport authentication.
//!
//! The HTTP host authenticates agents and human approvers separately. It prepares
//! registry-owned operations with validated arguments and authoritative scope,
//! then uses this store to decide whether an operation may begin. A token alone
//! never establishes the agent's identity. Restart discards every grant.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aws_lc_rs::{digest, hmac};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use zeroize::Zeroizing;

mod service;
pub(crate) use service::ApprovalRequiredOutput;
pub use service::ApprovalService;
pub(crate) use service::{
    ApprovalContext, SessionInput, SessionOutput, deserialize_optional_token,
};

/// Authenticated ownership, supplied by the host rather than MCP arguments.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalOwner {
    issuer: String,
    subject: String,
    actor: String,
}

impl ApprovalOwner {
    /// Bind the verified issuer, subject, and calling actor.
    ///
    /// # Errors
    /// Returns an error for empty, oversized, or control-bearing identity fields.
    pub fn new(issuer: String, subject: String, actor: String) -> Result<Self, ApprovalError> {
        if [&issuer, &subject, &actor]
            .into_iter()
            .any(|s| !identity(s))
        {
            return Err(ApprovalError::InvalidIdentity);
        }
        Ok(Self {
            issuer,
            subject,
            actor,
        })
    }
}

/// Human identity established by the host's independent approval boundary.
pub struct HumanApprover(String);

impl HumanApprover {
    /// Wrap an authenticated human identity; constructing this does not authenticate it.
    ///
    /// # Errors
    /// Returns an error for an invalid identity field.
    pub fn new(identity: String) -> Result<Self, ApprovalError> {
        if !self::identity(&identity) {
            return Err(ApprovalError::InvalidIdentity);
        }
        Ok(Self(identity))
    }
}

fn identity(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

/// Exact resource scope proven by the typed operation adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectEnvironment {
    /// Exact Infisical project identifier.
    project_id: String,
    /// Environment coordinate used by this operation's typed API request.
    environment: String,
}

impl ProjectEnvironment {
    /// Use the exact project identifier and environment coordinate consumed by the API.
    ///
    /// # Errors
    /// Returns an error for invalid scope identifiers.
    pub fn new(project_id: String, environment: String) -> Result<Self, ApprovalError> {
        if !identity(&project_id) || !identity(&environment) {
            return Err(ApprovalError::ScopeMismatch);
        }
        Ok(Self {
            project_id,
            environment,
        })
    }
}

/// Approval credential. Ordinary formatting never exposes its value.
pub struct ApprovalToken(Zeroizing<String>);

impl ApprovalToken {
    /// Parse an opaque token without retaining malformed input in an error.
    ///
    /// # Errors
    /// Returns the same refusal for every malformed credential.
    pub fn parse(value: String) -> Result<Self, ApprovalError> {
        let value = Zeroizing::new(value);
        if value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || URL_SAFE_NO_PAD
                .decode(value.as_bytes())
                .map(Zeroizing::new)
                .map_or(true, |v| v.len() != 32)
        {
            return Err(ApprovalError::UnknownSession);
        }
        Ok(Self(value))
    }

    /// Expose only at the authorized wire boundary; never include this in logs or URLs.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    fn hash(&self) -> [u8; 32] {
        digest::digest(&digest::SHA256, self.0.as_bytes())
            .as_ref()
            .try_into()
            .expect("SHA-256 length")
    }
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalToken([redacted])")
    }
}

impl fmt::Display for ApprovalToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Bounds for pending requests, grants, and retained in-flight approvals.
#[derive(Clone, Debug)]
pub struct ApprovalLimits {
    pub pending_ttl: Duration,
    pub once_ttl: Duration,
    pub max_duration: Duration,
    pub max_sessions: usize,
    pub max_pending_per_owner: usize,
}

impl Default for ApprovalLimits {
    fn default() -> Self {
        Self {
            pending_ttl: Duration::from_mins(15),
            once_ttl: Duration::from_mins(5),
            max_duration: Duration::from_hours(24),
            max_sessions: 1024,
            max_pending_per_owner: 16,
        }
    }
}

/// State visible to an authenticated client or human approval surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalState {
    Pending,
    Active,
    Denied,
    Expired,
    Revoked,
    Closed,
    Consumed,
}

/// The capability the human chose for this session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalMode {
    Once,
    Global,
    ProjectEnvironment,
}

/// Public metadata; it contains no tokens, credential values, or argument fingerprints.
#[derive(Clone, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalSession {
    /// Public request identifier; never an authorization credential.
    pub session_id: String,
    /// Registry operation that requested approval.
    pub operation: &'static str,
    /// Current approval lifecycle state.
    pub state: ApprovalState,
    /// Permission chosen by the human, if decided.
    pub mode: Option<ApprovalMode>,
    /// Exact project/environment restriction available for this operation.
    pub requested_scope: Option<ProjectEnvironment>,
    /// Bounded identifier and coordinate preview; never a complete argument dump.
    pub target: std::collections::BTreeMap<String, String>,
    /// Independently authenticated human who decided.
    pub approved_by: Option<String>,
    /// Seconds since the request was created.
    pub age_seconds: u64,
    /// Seconds remaining; querying never extends permission.
    pub remaining_seconds: u64,
    /// Single-use allowance; absent for timed permission.
    pub remaining_uses: Option<u8>,
}

/// The inactive credential is delivered once, together with its public metadata.
pub struct ApprovalChallenge {
    pub token: ApprovalToken,
    pub session: ApprovalSession,
}

/// A validated operation identity and a keyed fingerprint of all effective inputs.
#[derive(Clone)]
pub struct PreparedApproval {
    operation: &'static str,
    fingerprint: [u8; 32],
    scope: Option<ProjectEnvironment>,
    target: std::collections::BTreeMap<String, String>,
}

/// A human's decision; scoped approval always uses the request's proven scope.
#[derive(Clone, Copy)]
pub enum ApprovalDecision {
    ApproveOnce,
    ApproveFor {
        duration: Duration,
        scope: TimedScope,
    },
    Deny,
}

/// A timed grant is either client-global or restricted to the request's environment.
#[derive(Clone, Copy)]
pub enum TimedScope {
    Global,
    ProjectEnvironment,
}

/// Permission for one admitted operation, not a reusable client credential.
pub struct ApprovalPermit {
    session_hash: [u8; 32],
    operation: PreparedApproval,
}

/// A value-free event suitable for a host-owned required audit destination.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalEvent {
    pub kind: ApprovalEventKind,
    pub owner: ApprovalOwner,
    pub human: Option<String>,
    pub operation_scope: Option<ProjectEnvironment>,
    pub session: ApprovalSession,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalEventKind {
    Requested,
    Decided,
    Admitted,
    Closed,
    Revoked,
}

/// Failure to accept a required approval event; never carries sink error details.
#[derive(Debug)]
pub struct ApprovalRecordError;

/// The host accepts an event before permission takes effect.
///
/// Implementations must be bounded, synchronous, and must not reenter the store.
/// An accepted event's durability is the sink's contract, not the store's.
pub trait ApprovalRecorder: Send + Sync {
    /// # Errors
    /// Return an error if the required recording boundary did not accept the event.
    fn record(&self, event: &ApprovalEvent) -> Result<(), ApprovalRecordError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidConfiguration,
    InvalidIdentity,
    UnknownSession,
    Capacity,
    Pending,
    Denied,
    Expired,
    Revoked,
    Closed,
    Consumed,
    ScopeMismatch,
    RequestMismatch,
    AlreadyDecided,
    InvalidDuration,
    RecordingFailed,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "approval limits must be positive and consistent",
            Self::InvalidIdentity => "a bounded authenticated identity is required",
            Self::UnknownSession => "approval session is unavailable for this caller",
            Self::Capacity => "approval capacity is full; close an unused session or try later",
            Self::Pending => "human approval is still required",
            Self::Denied => "the human denied this approval request",
            Self::Expired => "approval expired; request fresh human approval",
            Self::Revoked => "the human revoked this approval",
            Self::Closed => "the client closed this approval session",
            Self::Consumed => "the single-use approval was already used",
            Self::ScopeMismatch => "the operation is outside the approved project and environment",
            Self::RequestMismatch => "this approval belongs to different operation arguments",
            Self::AlreadyDecided => "this request is no longer awaiting a human decision",
            Self::InvalidDuration => "choose a positive duration within the configured maximum",
            Self::RecordingFailed => {
                "required approval recording failed; inspect current session state"
            }
        })
    }
}

impl std::error::Error for ApprovalError {}

trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone)]
struct Session {
    id: String,
    owner: ApprovalOwner,
    request: PreparedApproval,
    created: Instant,
    deadline: Instant,
    state: ApprovalState,
    mode: Option<ApprovalMode>,
    human: Option<String>,
}

impl Session {
    fn refresh(&mut self, now: Instant) {
        if now >= self.deadline
            && matches!(
                self.state,
                ApprovalState::Pending | ApprovalState::Active | ApprovalState::Consumed
            )
        {
            self.state = ApprovalState::Expired;
        }
    }

    fn view(&self, now: Instant) -> ApprovalSession {
        let remaining = if matches!(
            self.state,
            ApprovalState::Pending | ApprovalState::Active | ApprovalState::Consumed
        ) {
            self.deadline.saturating_duration_since(now)
        } else {
            Duration::ZERO
        };
        ApprovalSession {
            session_id: self.id.clone(),
            operation: self.request.operation,
            state: self.state,
            mode: self.mode,
            requested_scope: self.request.scope.clone(),
            target: self.request.target.clone(),
            approved_by: self.human.clone(),
            age_seconds: now.saturating_duration_since(self.created).as_secs(),
            remaining_seconds: remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
            remaining_uses: (self.mode == Some(ApprovalMode::Once))
                .then_some(u8::from(self.state == ApprovalState::Active)),
        }
    }

    fn event(&self, kind: ApprovalEventKind, human: Option<String>, now: Instant) -> ApprovalEvent {
        ApprovalEvent {
            kind,
            owner: self.owner.clone(),
            human,
            operation_scope: self.request.scope.clone(),
            session: self.view(now),
        }
    }

    fn require_active(&self) -> Result<(), ApprovalError> {
        Err(match self.state {
            ApprovalState::Active => return Ok(()),
            ApprovalState::Pending => ApprovalError::Pending,
            ApprovalState::Denied => ApprovalError::Denied,
            ApprovalState::Expired => ApprovalError::Expired,
            ApprovalState::Revoked => ApprovalError::Revoked,
            ApprovalState::Closed => ApprovalError::Closed,
            ApprovalState::Consumed => ApprovalError::Consumed,
        })
    }
}

/// Bounded, instance-local approvals. Construct once and share across HTTP handlers.
pub struct ApprovalStore {
    limits: ApprovalLimits,
    fingerprint_key: hmac::Key,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    recorder: Arc<dyn ApprovalRecorder>,
    clock: Arc<dyn Clock>,
}

impl ApprovalStore {
    /// Create an empty authority with a fresh keyed-fingerprint secret.
    ///
    /// # Errors
    /// Returns an error for inconsistent limits.
    ///
    /// # Panics
    /// Panics if the platform CSPRNG is unavailable.
    pub fn new(
        limits: ApprovalLimits,
        recorder: Arc<dyn ApprovalRecorder>,
    ) -> Result<Self, ApprovalError> {
        let now = Instant::now();
        if limits.max_sessions == 0
            || limits.max_pending_per_owner == 0
            || limits.max_pending_per_owner > limits.max_sessions
            || [limits.pending_ttl, limits.once_ttl, limits.max_duration]
                .into_iter()
                .any(|d| d.is_zero() || now.checked_add(d).is_none())
        {
            return Err(ApprovalError::InvalidConfiguration);
        }
        let mut key = Zeroizing::new([0; 32]);
        aws_lc_rs::rand::fill(key.as_mut()).expect("platform CSPRNG");
        Ok(Self {
            limits,
            fingerprint_key: hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
            sessions: Mutex::new(HashMap::new()),
            recorder,
            clock: Arc::new(SystemClock),
        })
    }

    /// Fingerprint validated effective inputs, including delivery choices and file bindings.
    ///
    /// `operation` must come from the registry; `scope` must describe every effect.
    /// Use `None` when project/environment scope cannot be established safely.
    ///
    /// # Errors
    /// Returns an error if effective arguments cannot be serialized.
    ///
    /// # Panics
    /// Panics if the cryptographic library violates its HMAC-SHA256 output contract.
    pub fn prepare(
        &self,
        operation: &'static str,
        arguments: &Value,
        scope: Option<ProjectEnvironment>,
    ) -> Result<PreparedApproval, ApprovalError> {
        let mut writer = FingerprintWriter(hmac::Context::with_key(&self.fingerprint_key));
        serde_json::to_writer(&mut writer, &(operation, CanonicalValue(arguments), &scope))
            .map_err(|_| ApprovalError::RequestMismatch)?;
        let fingerprint = writer
            .0
            .sign()
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 length");
        Ok(PreparedApproval {
            operation,
            fingerprint,
            scope,
            target: std::collections::BTreeMap::new(),
        })
    }

    /// Ask for human approval without performing the operation or retaining credential inputs.
    ///
    /// # Errors
    /// Returns an error if capacity or the required recording boundary refuses the request.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned or the platform CSPRNG is unavailable.
    pub fn request(
        &self,
        owner: ApprovalOwner,
        request: PreparedApproval,
    ) -> Result<ApprovalChallenge, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        sessions.retain(|_, s| {
            s.refresh(now);
            matches!(
                s.state,
                ApprovalState::Pending | ApprovalState::Active | ApprovalState::Consumed
            )
        });
        if sessions.len() >= self.limits.max_sessions
            || sessions
                .values()
                .filter(|s| s.owner == owner && s.state == ApprovalState::Pending)
                .count()
                >= self.limits.max_pending_per_owner
        {
            return Err(ApprovalError::Capacity);
        }
        let token = ApprovalToken(Zeroizing::new(random_id()));
        let session = Session {
            id: random_id(),
            owner,
            request,
            created: now,
            deadline: now + self.limits.pending_ttl,
            state: ApprovalState::Pending,
            mode: None,
            human: None,
        };
        self.record(&session.event(ApprovalEventKind::Requested, None, now))?;
        let view = session.view(now);
        sessions.insert(token.hash(), session);
        Ok(ApprovalChallenge {
            token,
            session: view,
        })
    }

    /// Return owned session metadata without extending its lifetime.
    ///
    /// # Errors
    /// Returns an indistinguishable refusal for an unknown token or wrong owner.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn status(
        &self,
        owner: &ApprovalOwner,
        token: &ApprovalToken,
    ) -> Result<ApprovalSession, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        let session = owned(&mut sessions, owner, token)?;
        session.refresh(now);
        Ok(session.view(now))
    }

    /// Snapshot bounded metadata for the independently authenticated human surface.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    #[must_use]
    pub fn sessions(&self) -> Vec<(ApprovalOwner, ApprovalSession)> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        sessions
            .values_mut()
            .map(|session| {
                session.refresh(now);
                (session.owner.clone(), session.view(now))
            })
            .collect()
    }

    /// Apply a decision from the host's authenticated human surface.
    ///
    /// # Errors
    /// Refuses stale requests, unsupported scope, invalid duration, or failed recording.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn decide(
        &self,
        session_id: &str,
        human: &HumanApprover,
        decision: ApprovalDecision,
    ) -> Result<ApprovalSession, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        let session = sessions
            .values_mut()
            .find(|s| s.id == session_id)
            .ok_or(ApprovalError::UnknownSession)?;
        session.refresh(now);
        if session.state != ApprovalState::Pending {
            return Err(ApprovalError::AlreadyDecided);
        }
        let mut next = session.clone();
        next.human = Some(human.0.clone());
        let (mode, ttl) = match decision {
            ApprovalDecision::Deny => {
                next.state = ApprovalState::Denied;
                (None, Duration::ZERO)
            }
            ApprovalDecision::ApproveOnce => (Some(ApprovalMode::Once), self.limits.once_ttl),
            ApprovalDecision::ApproveFor { duration, scope } => {
                if duration.is_zero() || duration > self.limits.max_duration {
                    return Err(ApprovalError::InvalidDuration);
                }
                let mode = match scope {
                    TimedScope::Global => ApprovalMode::Global,
                    TimedScope::ProjectEnvironment => {
                        if next.request.scope.is_none() {
                            return Err(ApprovalError::ScopeMismatch);
                        }
                        ApprovalMode::ProjectEnvironment
                    }
                };
                (Some(mode), duration)
            }
        };
        if let Some(mode) = mode {
            next.state = ApprovalState::Active;
            next.mode = Some(mode);
            next.deadline = now + ttl;
        }
        self.record(&next.event(ApprovalEventKind::Decided, next.human.clone(), now))?;
        *session = next;
        Ok(session.view(now))
    }

    /// Atomically authorize one operation and consume an exact single-use grant.
    ///
    /// # Errors
    /// Refuses inactive grants, ownership/argument/scope mismatch, or failed recording.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn admit(
        &self,
        owner: &ApprovalOwner,
        token: &ApprovalToken,
        operation: PreparedApproval,
    ) -> Result<ApprovalPermit, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        let session = owned(&mut sessions, owner, token)?;
        session.refresh(now);
        session.require_active()?;
        match session.mode.expect("active session has a mode") {
            ApprovalMode::Once if session.request.fingerprint != operation.fingerprint => {
                return Err(ApprovalError::RequestMismatch);
            }
            ApprovalMode::ProjectEnvironment
                if operation.scope.is_none() || operation.scope != session.request.scope =>
            {
                return Err(ApprovalError::ScopeMismatch);
            }
            _ => {}
        }
        let mut next = session.clone();
        if next.mode == Some(ApprovalMode::Once) {
            next.state = ApprovalState::Consumed;
        }
        let mut event = next.event(ApprovalEventKind::Admitted, next.human.clone(), now);
        event.session.operation = operation.operation;
        event.operation_scope.clone_from(&operation.scope);
        self.record(&event)?;
        *session = next;
        Ok(ApprovalPermit {
            session_hash: token.hash(),
            operation,
        })
    }

    /// Recheck a permit after waits and before registering the next upstream action.
    ///
    /// A consumed once-grant remains valid only for the attempt that consumed it.
    /// This check cannot undo an action the host has already sent upstream.
    ///
    /// # Errors
    /// Refuses expired, revoked, closed, or unavailable approval.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn check(&self, permit: &ApprovalPermit) -> Result<(), ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let session = sessions
            .get_mut(&permit.session_hash)
            .ok_or(ApprovalError::UnknownSession)?;
        session.refresh(self.clock.now());
        if session.state == ApprovalState::Consumed
            && session.request.fingerprint == permit.operation.fingerprint
        {
            return Ok(());
        }
        session.require_active()
    }

    /// Close an owned session. Repeated close is harmless and never reopens it.
    ///
    /// # Errors
    /// Refuses unknown ownership. Recording failure is reported after closure;
    /// permission remains closed regardless of the recording outcome.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn close(
        &self,
        owner: &ApprovalOwner,
        token: &ApprovalToken,
    ) -> Result<ApprovalSession, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        let session = owned(&mut sessions, owner, token)?;
        if session.state != ApprovalState::Closed {
            session.state = ApprovalState::Closed;
            self.record(&session.event(ApprovalEventKind::Closed, None, now))?;
        }
        Ok(session.view(now))
    }

    /// Revoke a grant from the host's authenticated human surface.
    ///
    /// # Errors
    /// Refuses an unknown session. A recording error does not undo revocation.
    ///
    /// # Panics
    /// Panics if the state lock is poisoned.
    pub fn revoke(
        &self,
        session_id: &str,
        human: &HumanApprover,
    ) -> Result<ApprovalSession, ApprovalError> {
        let mut sessions = self.sessions.lock().expect("approval state lock");
        let now = self.clock.now();
        let session = sessions
            .values_mut()
            .find(|s| s.id == session_id)
            .ok_or(ApprovalError::UnknownSession)?;
        if session.state != ApprovalState::Revoked {
            session.state = ApprovalState::Revoked;
            self.record(&session.event(ApprovalEventKind::Revoked, Some(human.0.clone()), now))?;
        }
        Ok(session.view(now))
    }

    fn record(&self, event: &ApprovalEvent) -> Result<(), ApprovalError> {
        self.recorder
            .record(event)
            .map_err(|_| ApprovalError::RecordingFailed)
    }
}

fn owned<'a>(
    sessions: &'a mut HashMap<[u8; 32], Session>,
    owner: &ApprovalOwner,
    token: &ApprovalToken,
) -> Result<&'a mut Session, ApprovalError> {
    sessions
        .get_mut(&token.hash())
        .filter(|s| s.owner == *owner)
        .ok_or(ApprovalError::UnknownSession)
}

fn random_id() -> String {
    let mut bytes = Zeroizing::new([0; 32]);
    aws_lc_rs::rand::fill(bytes.as_mut()).expect("platform CSPRNG");
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

/// Sort every object, including nested ones, independently of map feature flags.
struct CanonicalValue<'a>(&'a Value);

// Feed serialization into the vetted HMAC implementation without allocating a
// plaintext output buffer whose growth could release unwiped secret bytes.
struct FingerprintWriter(hmac::Context);

impl std::io::Write for FingerprintWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Serialize for CanonicalValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(object) => {
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable();
                let mut map = serializer.serialize_map(Some(keys.len()))?;
                for key in keys {
                    map.serialize_entry(key, &CanonicalValue(&object[key]))?;
                }
                map.end()
            }
            Value::Array(values) => serializer.collect_seq(values.iter().map(CanonicalValue)),
            other => other.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests;
