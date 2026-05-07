//! Native PKCS#11 bridge for `pkcs11ex`.
//!
//! Phase 1 surface: load a module (with optional integrity pinning), enumerate
//! slots, sign / verify against a key found by label, and a test-only
//! `generate_rsa_keypair` for fixture provisioning.
//!
//! Subsequent steps will introduce per-slot session pools, single-session-pinned
//! handling for PIN-protected tokens, and stable opaque key handles. For now,
//! `sign` / `verify` open a session per call — correct, simple, inefficient.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session as CkSession, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use parking_lot::Mutex;
use rustler::{Binary, Encoder, Env, NifStruct, Resource, ResourceArc, Term};
use sha2::{Digest, Sha256};
use std::fs;
use std::panic::{RefUnwindSafe, UnwindSafe};
use zeroize::Zeroizing;

mod atoms {
    rustler::atoms! {
        ok,
        // Errors
        driver_load_failed,
        driver_pin_mismatch,
        pkcs11_error,
        slot_invalid,
        key_not_found,
        signature_invalid,
        unsupported_mechanism,
        user_already_logged_in,
    }
}

// ---------- Resources ----------

pub struct Module {
    pkcs11: Pkcs11,
}

impl RefUnwindSafe for Module {}
impl UnwindSafe for Module {}

#[rustler::resource_impl]
impl Resource for Module {}

/// Owns a PKCS#11 session for the lifetime of the resource.
///
/// Wrapped in `parking_lot::Mutex` because PKCS#11 sessions are NOT thread-safe
/// per the standard — at most one thread may use a given session concurrently.
/// The Mutex makes `Session` `Sync` (Rustler's resource requirement) and
/// serializes access. For PIN-protected token slots this matches the spec's
/// "single-session-pinned" model. For cloud HSM slots that benefit from
/// parallel sessions, a per-slot pool of these resources can be added later
/// without changing this type.
pub struct Session {
    inner: Mutex<CkSession>,
}

impl RefUnwindSafe for Session {}
impl UnwindSafe for Session {}

#[rustler::resource_impl]
impl Resource for Session {}

// ---------- Errors ----------

pub enum Error {
    DriverLoadFailed(String),
    DriverPinMismatch { expected: String, got: String },
    Pkcs11(String),
    SlotInvalid(u64),
    KeyNotFound(String),
    SignatureInvalid,
    UnsupportedMechanism(String),
    UserAlreadyLoggedIn,
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        // Map well-known RvErrors to their own variants so the Elixir caller
        // gets typed atoms rather than substring-matching against
        // `pkcs11_error` strings. Other mappings (CKR_PIN_INCORRECT,
        // CKR_PIN_LOCKED, etc.) land in a later step.
        if let cryptoki::error::Error::Pkcs11(rv, _) = &e {
            match rv {
                cryptoki::error::RvError::SignatureInvalid => return Error::SignatureInvalid,
                cryptoki::error::RvError::UserAlreadyLoggedIn => return Error::UserAlreadyLoggedIn,
                _ => {}
            }
        }
        Error::Pkcs11(format!("{e}"))
    }
}

impl Encoder for Error {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            Error::DriverLoadFailed(msg) => (atoms::driver_load_failed(), msg.as_str()).encode(env),
            Error::DriverPinMismatch { expected, got } => {
                (atoms::driver_pin_mismatch(), expected.as_str(), got.as_str()).encode(env)
            }
            Error::Pkcs11(msg) => (atoms::pkcs11_error(), msg.as_str()).encode(env),
            Error::SlotInvalid(id) => (atoms::slot_invalid(), *id).encode(env),
            Error::KeyNotFound(label) => (atoms::key_not_found(), label.as_str()).encode(env),
            Error::SignatureInvalid => atoms::signature_invalid().encode(env),
            Error::UnsupportedMechanism(name) => {
                (atoms::unsupported_mechanism(), name.as_str()).encode(env)
            }
            Error::UserAlreadyLoggedIn => atoms::user_already_logged_in().encode(env),
        }
    }
}

// ---------- Encodable structs ----------

#[derive(NifStruct)]
#[module = "Pkcs11ex.Native.RsaPrivateComponents"]
pub struct RsaPrivateComponents {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub prime1: Vec<u8>,
    pub prime2: Vec<u8>,
    pub exponent1: Vec<u8>,
    pub exponent2: Vec<u8>,
    pub coefficient: Vec<u8>,
}

#[derive(NifStruct)]
#[module = "Pkcs11ex.Native.SlotInfo"]
pub struct SlotInfo {
    pub slot_id: u64,
    pub description: String,
    pub manufacturer: String,
    pub token_present: bool,
    /// Trimmed `CKA_LABEL` from `CK_TOKEN_INFO` when a token is present and
    /// initialized. Empty string when no token or token uninitialized — this
    /// is how SoftHSM2's "free slot" (CKF_TOKEN_PRESENT but uninitialized)
    /// can be distinguished from a real initialized token.
    pub token_label: String,
}

// ---------- Helpers ----------

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn load_initialized(path: &str) -> Result<Pkcs11, Error> {
    let pkcs11 = Pkcs11::new(path).map_err(|e| Error::DriverLoadFailed(format!("{e}")))?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    Ok(pkcs11)
}

fn slot_for(slot_id: u64) -> Result<Slot, Error> {
    Slot::try_from(slot_id).map_err(|_| Error::SlotInvalid(slot_id))
}

fn open_session(module: &Module, slot_id: u64, pin: &str) -> Result<CkSession, Error> {
    let slot = slot_for(slot_id)?;
    let session = module.pkcs11.open_rw_session(slot)?;

    if !pin.is_empty() {
        session.login(UserType::User, Some(&AuthPin::new(pin.into())))?;
    }

    Ok(session)
}

fn build_mechanism(name: &str) -> Result<Mechanism<'_>, Error> {
    match name {
        "ck_sha256_rsa_pkcs_pss" => Ok(Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: 32u64.into(),
        })),
        other => Err(Error::UnsupportedMechanism(other.to_string())),
    }
}

fn find_key(session: &CkSession, class: ObjectClass, label: &str) -> Result<ObjectHandle, Error> {
    let template = vec![
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let handles = session.find_objects(&template)?;

    handles
        .into_iter()
        .next()
        .ok_or_else(|| Error::KeyNotFound(label.to_string()))
}

// ---------- NIFs ----------

#[rustler::nif]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[rustler::nif(schedule = "DirtyIo")]
fn module_load(path: String) -> Result<ResourceArc<Module>, Error> {
    let pkcs11 = load_initialized(&path)?;
    Ok(ResourceArc::new(Module { pkcs11 }))
}

#[rustler::nif(schedule = "DirtyIo")]
fn module_load_pinned(
    path: String,
    expected_sha256_hex: String,
) -> Result<ResourceArc<Module>, Error> {
    let bytes =
        fs::read(&path).map_err(|e| Error::DriverLoadFailed(format!("read failed: {e}")))?;
    let actual = sha256_hex(&bytes);
    let expected = expected_sha256_hex.to_lowercase();

    if actual != expected {
        return Err(Error::DriverPinMismatch {
            expected,
            got: actual,
        });
    }

    let pkcs11 = load_initialized(&path)?;
    Ok(ResourceArc::new(Module { pkcs11 }))
}

#[rustler::nif(schedule = "DirtyIo")]
fn list_slots(module: ResourceArc<Module>) -> Result<Vec<SlotInfo>, Error> {
    let slots = module.pkcs11.get_all_slots()?;

    let mut result = Vec::with_capacity(slots.len());
    for slot in slots {
        let info = module.pkcs11.get_slot_info(slot)?;
        let token_present = info.token_present();

        let token_label = if token_present {
            match module.pkcs11.get_token_info(slot) {
                Ok(ti) if ti.token_initialized() => ti.label().trim().to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        };

        result.push(SlotInfo {
            slot_id: slot.id(),
            description: info.slot_description().trim().to_string(),
            manufacturer: info.manufacturer_id().trim().to_string(),
            token_present,
            token_label,
        });
    }

    Ok(result)
}

/// Sign `data` with a key found by label on the given slot.
///
/// `pin` is empty string for "no login" (cloud HSMs without User PIN), or the
/// User PIN for token slots. Encoding `pin` as `Option<String>` would be more
/// natural but Rustler 0.36's decode path is finicky with `Option<String>`
/// across nil/binary; sentinel-empty-string keeps the NIF surface simple.
#[rustler::nif(schedule = "DirtyIo")]
fn sign(
    module: ResourceArc<Module>,
    slot_id: u64,
    pin: String,
    mechanism: String,
    key_label: String,
    data: Binary<'_>,
) -> Result<Vec<u8>, Error> {
    let session = open_session(&module, slot_id, &pin)?;
    let mech = build_mechanism(&mechanism)?;
    let key = find_key(&session, ObjectClass::PRIVATE_KEY, &key_label)?;
    let signature = session.sign(&mech, key, data.as_slice())?;
    Ok(signature)
}

#[rustler::nif(schedule = "DirtyIo")]
fn verify(
    module: ResourceArc<Module>,
    slot_id: u64,
    mechanism: String,
    key_label: String,
    data: Binary<'_>,
    signature: Binary<'_>,
) -> Result<bool, Error> {
    // Verify is a public-key operation; no login required.
    let session = open_session(&module, slot_id, "")?;
    let mech = build_mechanism(&mechanism)?;
    let key = find_key(&session, ObjectClass::PUBLIC_KEY, &key_label)?;

    match session.verify(&mech, key, data.as_slice(), signature.as_slice()) {
        Ok(()) => Ok(true),
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureInvalid, _)) => {
            Err(Error::SignatureInvalid)
        }
        Err(e) => Err(Error::from(e)),
    }
}

// ---------- Stateful session NIFs (Phase 2) ----------

/// Opens a long-lived RW session against a slot. The returned resource lives
/// until either it goes out of scope (Drop runs `C_CloseSession` via cryptoki)
/// or `session_close/1` is called explicitly.
#[rustler::nif(schedule = "DirtyIo")]
fn session_open(module: ResourceArc<Module>, slot_id: u64) -> Result<ResourceArc<Session>, Error> {
    let slot = slot_for(slot_id)?;
    let ck_session = module.pkcs11.open_rw_session(slot)?;
    Ok(ResourceArc::new(Session {
        inner: Mutex::new(ck_session),
    }))
}

/// Calls `C_Login(CKU_USER, pin)` on the session.
///
/// PIN handling is the layered model from `specs.md` §5.2:
///   - The Erlang binary backing `pin` is BEAM-managed and **cannot** be
///     wiped from Rust. Applications keep its lifetime short by passing it
///     directly from a `pin_callback` and never storing it.
///   - Rust copies the bytes once into a `Zeroizing<Vec<u8>>` which is
///     wiped on drop. The cryptoki `AuthPin` (a `SecretString`) zeroizes
///     its internal buffer on drop too. Both are dropped at the end of
///     this function.
///
/// Calling on an already-logged-in session returns `CKR_USER_ALREADY_LOGGED_IN`
/// from cryptoki — propagated so the Elixir side can recover.
#[rustler::nif(schedule = "DirtyIo")]
fn session_login(session: ResourceArc<Session>, pin: Binary<'_>) -> Result<bool, Error> {
    let lock = session.inner.lock();

    let pin_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(pin.as_slice().to_vec());
    let pin_str = std::str::from_utf8(&pin_bytes)
        .map_err(|_| Error::Pkcs11("PIN must be valid UTF-8".into()))?;

    let auth = AuthPin::new(pin_str.to_string().into_boxed_str());
    lock.login(UserType::User, Some(&auth))?;
    Ok(true)
}

/// Calls `C_Logout` on the session. Does not close the session itself.
#[rustler::nif(schedule = "DirtyIo")]
fn session_logout(session: ResourceArc<Session>) -> Result<bool, Error> {
    let lock = session.inner.lock();
    lock.logout()?;
    Ok(true)
}

/// Sign with a key found by label in the given session's slot. Acquires the
/// session mutex for the duration of the operation, serializing concurrent
/// sign requests through the same session (the PKCS#11 thread-safety rule).
#[rustler::nif(schedule = "DirtyIo")]
fn sign_with_session(
    session: ResourceArc<Session>,
    mechanism: String,
    key_label: String,
    data: Binary<'_>,
) -> Result<Vec<u8>, Error> {
    let lock = session.inner.lock();
    let mech = build_mechanism(&mechanism)?;
    let key = find_key(&lock, ObjectClass::PRIVATE_KEY, &key_label)?;
    let signature = lock.sign(&mech, key, data.as_slice())?;
    Ok(signature)
}

/// Verify with a key found by label in the given session's slot. Acquires
/// the session mutex for the duration. Verification is a public-key
/// operation — no login required — but we still go through the session
/// because the cryptoki API is session-based.
#[rustler::nif(schedule = "DirtyIo")]
fn verify_with_session(
    session: ResourceArc<Session>,
    mechanism: String,
    key_label: String,
    data: Binary<'_>,
    signature: Binary<'_>,
) -> Result<bool, Error> {
    let lock = session.inner.lock();
    let mech = build_mechanism(&mechanism)?;
    let key = find_key(&lock, ObjectClass::PUBLIC_KEY, &key_label)?;

    match lock.verify(&mech, key, data.as_slice(), signature.as_slice()) {
        Ok(()) => Ok(true),
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::SignatureInvalid, _)) => {
            Err(Error::SignatureInvalid)
        }
        Err(e) => Err(Error::from(e)),
    }
}

/// Test-only helper: read the modulus and public exponent of an RSA public
/// key on the slot. Used by JWS round-trip tests to build a self-signed
/// certificate that wraps the SoftHSM-resident key, so software-side verify
/// can mathematically check the SoftHSM-produced signature.
///
/// Returns `(modulus, public_exponent)`. Both are big-endian unsigned integer
/// byte strings (DER `INTEGER` content, leading zero byte omitted).
#[rustler::nif(schedule = "DirtyIo")]
fn export_rsa_public_key(
    module: ResourceArc<Module>,
    slot_id: u64,
    key_label: String,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let session = open_session(&module, slot_id, "")?;
    let key = find_key(&session, ObjectClass::PUBLIC_KEY, &key_label)?;

    let attrs =
        session.get_attributes(key, &[AttributeType::Modulus, AttributeType::PublicExponent])?;

    let mut modulus: Option<Vec<u8>> = None;
    let mut exponent: Option<Vec<u8>> = None;

    for attr in attrs {
        match attr {
            Attribute::Modulus(m) => modulus = Some(m),
            Attribute::PublicExponent(e) => exponent = Some(e),
            _ => {}
        }
    }

    let modulus = modulus.ok_or_else(|| Error::Pkcs11("CKA_MODULUS not returned".into()))?;
    let exponent =
        exponent.ok_or_else(|| Error::Pkcs11("CKA_PUBLIC_EXPONENT not returned".into()))?;

    Ok((modulus, exponent))
}

/// Test-only / provisioning helper: generate an RSA-2048 keypair on the slot
/// with the given label. Used by integration tests against SoftHSM2; not part
/// of the public Pkcs11ex.* surface (key-lifecycle management is a non-goal,
/// per specs.md §10).
#[rustler::nif(schedule = "DirtyIo")]
fn generate_rsa_keypair(
    module: ResourceArc<Module>,
    slot_id: u64,
    pin: String,
    label: String,
    bits: u32,
) -> Result<bool, Error> {
    let session = open_session(&module, slot_id, &pin)?;

    let public_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::ModulusBits((bits as u64).into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let private_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let _ = session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &public_template,
        &private_template,
    )?;

    Ok(true)
}

// ---------- Provisioning NIFs (Mix task only) ----------

/// Import an RSA private key into the slot's session.
///
/// Used exclusively by `mix pkcs11ex.import_p12` for provisioning. The
/// caller is responsible for not leaking the components beyond the import
/// flow — this NIF takes them as plain `Vec<u8>` rather than zeroizing
/// containers because they're already plaintext on the calling stack.
///
/// `id` is a `CKA_ID` byte string; pass an empty binary to omit.
#[rustler::nif(schedule = "DirtyIo")]
fn import_rsa_private_key(
    session: ResourceArc<Session>,
    label: String,
    id: Binary<'_>,
    components: RsaPrivateComponents,
) -> Result<bool, Error> {
    let lock = session.inner.lock();

    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(label.into_bytes()),
        Attribute::Modulus(components.modulus),
        Attribute::PublicExponent(components.public_exponent),
        Attribute::PrivateExponent(components.private_exponent),
        Attribute::Prime1(components.prime1),
        Attribute::Prime2(components.prime2),
        Attribute::Exponent1(components.exponent1),
        Attribute::Exponent2(components.exponent2),
        Attribute::Coefficient(components.coefficient),
    ];

    if !id.is_empty() {
        template.push(Attribute::Id(id.as_slice().to_vec()));
    }

    let _ = lock.create_object(&template)?;
    Ok(true)
}

/// Import an X.509 certificate into the slot's session.
#[rustler::nif(schedule = "DirtyIo")]
fn import_x509_certificate(
    session: ResourceArc<Session>,
    label: String,
    id: Binary<'_>,
    subject_der: Binary<'_>,
    cert_der: Binary<'_>,
) -> Result<bool, Error> {
    let lock = session.inner.lock();

    let mut template = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Label(label.into_bytes()),
        Attribute::Subject(subject_der.as_slice().to_vec()),
        Attribute::Value(cert_der.as_slice().to_vec()),
    ];

    if !id.is_empty() {
        template.push(Attribute::Id(id.as_slice().to_vec()));
    }

    let _ = lock.create_object(&template)?;
    Ok(true)
}

rustler::init!("Elixir.Pkcs11ex.Native");
