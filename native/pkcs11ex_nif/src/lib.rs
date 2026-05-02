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
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use rustler::{Binary, Encoder, Env, NifStruct, Resource, ResourceArc, Term};
use sha2::{Digest, Sha256};
use std::fs;
use std::panic::{RefUnwindSafe, UnwindSafe};

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

// ---------- Errors ----------

pub enum Error {
    DriverLoadFailed(String),
    DriverPinMismatch { expected: String, got: String },
    Pkcs11(String),
    SlotInvalid(u64),
    KeyNotFound(String),
    SignatureInvalid,
    UnsupportedMechanism(String),
}

impl From<cryptoki::error::Error> for Error {
    fn from(e: cryptoki::error::Error) -> Self {
        // Map signature-invalid to its own variant so the Elixir caller gets a
        // typed atom rather than an opaque pkcs11_error tuple. Other mappings
        // (CKR_PIN_INCORRECT, CKR_PIN_LOCKED, etc.) land in a later step.
        if let cryptoki::error::Error::Pkcs11(rv, _) = &e {
            if *rv == cryptoki::error::RvError::SignatureInvalid {
                return Error::SignatureInvalid;
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
        }
    }
}

// ---------- Encodable structs ----------

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

fn open_session(module: &Module, slot_id: u64, pin: &str) -> Result<Session, Error> {
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

fn find_key(session: &Session, class: ObjectClass, label: &str) -> Result<ObjectHandle, Error> {
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

rustler::init!("Elixir.Pkcs11ex.Native");
