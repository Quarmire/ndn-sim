//! The signal wire as the signals spec writes it (ndn-rs `docs/specs/signals.md` §4), written
//! here from the spec alone so the signal cases (`e1`…`e17`) can make, capture and inspect
//! packets the way an attacker or a relay sees them: a run header signed by a device key, a
//! SignalBody signed by a run key, a SignalSealed under a scope's signal key, and the unsigned
//! push Interest that carries one into a namespace's sync group. It shares no code with
//! `ndn-surface`'s hub, so a packet the hub refuses or accepts here is judged against the spec,
//! not against the hub's own encoder.

use bytes::Bytes;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as _, SigningKey};
use ndn_data::Name;
use ndn_packet::Interest;
use ndn_packet::encode::InterestBuilder;
use sha2::{Digest, Sha256};

/// The context every run signature and every seal binds (spec §4).
pub const CONTEXT: &[u8] = b"ndn-signal/2";

/// SignalBody: ScopeDigest, RunId, [RunHeader], Signal*, RunSignature.
pub const SIGNAL_BODY: u64 = 0x0580;
/// SignalSealed: KeyId, SealNonce, Ciphertext.
pub const SIGNAL_SEALED: u64 = 0x0582;
const KEY_ID: u64 = 0x0584;
const SEAL_NONCE: u64 = 0x0586;
const CIPHERTEXT: u64 = 0x0588;
const RUN_ID: u64 = 0x058A;
const RUN_HEADER: u64 = 0x058C;
const SIGNAL: u64 = 0x058E;
const SIGNAL_SEQ: u64 = 0x0590;
const ADDRESS: u64 = 0x0592;
const EXPIRES: u64 = 0x0594;
const PAYLOAD: u64 = 0x0596;
const RUN_SIGNATURE: u64 = 0x0598;
const RUN_HEADER_BODY: u64 = 0x059A;
const RUN_KEY: u64 = 0x059C;
const RUN_START: u64 = 0x059E;
const RUN_NOT_AFTER: u64 = 0x05A0;
const LOCAL_RING: u64 = 0x05A2;
const SIGNAL_PADDING: u64 = 0x05A4;
const SCOPE_DIGEST: u64 = 0x05A6;
/// The first 16 octets of SHA-256 over `"ndn-signal/2 scope"` and `scope`'s Name TLV: what a
/// packet names its scope by after the run's header (spec §4.1).
pub fn scope_digest(scope: &Name) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"ndn-signal/2 scope");
    hash.update(scope.encode_to_tlv());
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&hash.finalize()[..16]);
    digest
}
/// The typed component of `32=signal`.
const KEYWORD: u64 = 32;

/// A run's Ed25519 key, made from a seed so a case replays the same bytes every run.
pub struct RunKey(SigningKey);

impl RunKey {
    /// The run key whose secret is `seed`.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Its public key, as RunKey carries it.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Its RunId: the first 16 octets of SHA-256 of its public key.
    pub fn id(&self) -> [u8; 16] {
        run_id(&self.public())
    }
}

/// The RunId of the run whose public key is `public`.
pub fn run_id(public: &[u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(public);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// One signal of a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub seq: u64,
    pub address: Bytes,
    /// Milliseconds since the Unix epoch, by the sender's clock.
    pub expires: u64,
    pub payload: Bytes,
}

/// A SignalBody as decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// The packet's ScopeDigest.
    pub digest: [u8; 16],
    pub run: [u8; 16],
    /// The run header's whole Data wire, when it rides in this packet.
    pub header: Option<Bytes>,
    pub signals: Vec<Signal>,
    pub signature: Bytes,
}

/// A SignalSealed as decoded: what a relay can read of a sealed packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: [u8; 8],
    pub nonce: [u8; 24],
    pub ciphertext: Bytes,
}

/// The name of a run header: `<signer device>/32=signal/<scope>/32=run/<run id>`.
pub fn header_name(signer: &Name, scope: &Name, run: &[u8; 16]) -> Name {
    let mut name = signer.clone().append_component(keyword(b"signal"));
    for c in scope.components() {
        name = name.append_component(c.clone());
    }
    name.append_component(keyword(b"run")).append(run)
}

/// A run header's Content (RunHeaderBody): the run key, its first sequence and its end, no ring.
pub fn header_content(public: &[u8; 32], start: u64, not_after: u64) -> Bytes {
    header_body(public, start, not_after, None)
}

/// A run header's Content that also names a local ring by its secret (`LocalRing`).
pub fn header_content_ring(
    public: &[u8; 32],
    start: u64,
    not_after: u64,
    ring: &[u8; 32],
) -> Bytes {
    header_body(public, start, not_after, Some(ring))
}

fn header_body(public: &[u8; 32], start: u64, not_after: u64, ring: Option<&[u8; 32]>) -> Bytes {
    let mut value = Vec::new();
    tlv(&mut value, RUN_KEY, public);
    tlv(&mut value, RUN_START, &nni(start));
    tlv(&mut value, RUN_NOT_AFTER, &nni(not_after));
    if let Some(ring) = ring {
        tlv(&mut value, LOCAL_RING, ring);
    }
    let mut out = Vec::new();
    tlv(&mut out, RUN_HEADER_BODY, &value);
    out.into()
}

/// The RunKey a run header's Content binds.
pub fn header_run_key(content: &[u8]) -> Option<[u8; 32]> {
    let (typ, value, _) = read(content)?;
    if typ != RUN_HEADER_BODY {
        return None;
    }
    let (typ, key, _) = read(value)?;
    (typ == RUN_KEY).then(|| key.try_into().ok()).flatten()
}

/// A SignalBody TLV over `scope` (named by its digest, never its Name), claiming run `run`,
/// carrying `header` and `signals`, its run signature made by `key` (which need not be the
/// run's: a forger's).
pub fn body(
    scope: &Name,
    run: &[u8; 16],
    header: Option<&[u8]>,
    signals: &[Signal],
    key: &RunKey,
) -> Bytes {
    let mut value = Vec::new();
    tlv(&mut value, SCOPE_DIGEST, &scope_digest(scope));
    tlv(&mut value, RUN_ID, run);
    if let Some(header) = header {
        tlv(&mut value, RUN_HEADER, header);
    }
    for s in signals {
        let mut one = Vec::new();
        tlv(&mut one, SIGNAL_SEQ, &nni(s.seq));
        tlv(&mut one, ADDRESS, &s.address);
        tlv(&mut one, EXPIRES, &nni(s.expires));
        tlv(&mut one, PAYLOAD, &s.payload);
        tlv(&mut value, SIGNAL, &one);
    }
    let mut signed = CONTEXT.to_vec();
    signed.extend_from_slice(&value);
    tlv(&mut value, RUN_SIGNATURE, &key.0.sign(&signed).to_bytes());
    let mut out = Vec::new();
    tlv(&mut out, SIGNAL_BODY, &value);
    out.into()
}

/// `body` (a SignalBody TLV) sealed under the signal key `key` whose id is `key_id`, with
/// `nonce`: a SignalSealed TLV.
pub fn seal(key_id: &[u8; 8], key: &[u8; 32], nonce: &[u8; 24], body: &[u8]) -> Bytes {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: body,
                aad: &aad(key_id),
            },
        )
        .expect("XChaCha20-Poly1305 seals any packet under 1,024 octets");
    let mut value = Vec::new();
    tlv(&mut value, KEY_ID, key_id);
    tlv(&mut value, SEAL_NONCE, nonce);
    tlv(&mut value, CIPHERTEXT, &ciphertext);
    let mut out = Vec::new();
    tlv(&mut out, SIGNAL_SEALED, &value);
    out.into()
}

/// The SignalSealed `packet` is, if it is one: exactly KeyId, SealNonce, Ciphertext, nothing
/// before, between or after them.
pub fn sealed(packet: &[u8]) -> Option<Sealed> {
    let (typ, value, rest) = read(packet)?;
    if typ != SIGNAL_SEALED || !rest.is_empty() {
        return None;
    }
    let (t1, key_id, value) = read(value)?;
    let (t2, nonce, value) = read(value)?;
    let (t3, ciphertext, value) = read(value)?;
    if (t1, t2, t3) != (KEY_ID, SEAL_NONCE, CIPHERTEXT) || !value.is_empty() {
        return None;
    }
    Some(Sealed {
        key_id: key_id.try_into().ok()?,
        nonce: nonce.try_into().ok()?,
        ciphertext: Bytes::copy_from_slice(ciphertext),
    })
}

/// The SignalBody TLV inside `sealed`, opened with the signal key `key`, without the one
/// SignalPadding that may follow it in the plaintext; `None` when it does not open under it
/// or its plaintext is anything else.
pub fn open(sealed: &Sealed, key: &[u8; 32]) -> Option<Bytes> {
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &aad(&sealed.key_id),
            },
        )
        .ok()?;
    let (_, _, rest) = read(&plain)?;
    let body = plain.len() - rest.len();
    if !rest.is_empty() {
        let (typ, _, after) = read(rest)?;
        if typ != SIGNAL_PADDING || !after.is_empty() {
            return None;
        }
    }
    Some(Bytes::from(plain).slice(..body))
}

/// The SignalBody `packet` is, if it is one.
pub fn parse_body(packet: &[u8]) -> Option<Body> {
    let (typ, mut value, rest) = read(packet)?;
    if typ != SIGNAL_BODY || !rest.is_empty() {
        return None;
    }
    let (typ, digest, after) = read(value)?;
    if typ != SCOPE_DIGEST {
        return None;
    }
    let digest: [u8; 16] = digest.try_into().ok()?;
    value = after;
    let (typ, run, after) = read(value)?;
    if typ != RUN_ID {
        return None;
    }
    let run: [u8; 16] = run.try_into().ok()?;
    value = after;
    let mut header = None;
    let mut signals = Vec::new();
    loop {
        let (typ, v, after) = read(value)?;
        value = after;
        match typ {
            RUN_HEADER => header = Some(Bytes::copy_from_slice(v)),
            SIGNAL => signals.push(parse_signal(v)?),
            RUN_SIGNATURE if value.is_empty() => {
                return Some(Body {
                    digest,
                    run,
                    header,
                    signals,
                    signature: Bytes::copy_from_slice(v),
                });
            }
            _ => return None,
        }
    }
}

fn parse_signal(mut value: &[u8]) -> Option<Signal> {
    let mut field = |want: u64| {
        let (typ, v, after) = read(value)?;
        value = after;
        (typ == want).then_some(v)
    };
    let seq = from_nni(field(SIGNAL_SEQ)?)?;
    let address = Bytes::copy_from_slice(field(ADDRESS)?);
    let expires = from_nni(field(EXPIRES)?)?;
    let payload = Bytes::copy_from_slice(field(PAYLOAD)?);
    Some(Signal {
        seq,
        address,
        expires,
        payload,
    })
}

/// The push Interest carrying `packet` into the sync group `group` (`<O>/32=sync`):
/// `<group>/32=signal/<ParametersSha256Digest>`, the packet its ApplicationParameters,
/// InterestLifetime 1 s, HopLimit 8, unsigned. Each build draws a fresh Nonce.
pub fn push(group: &Name, packet: &[u8]) -> Bytes {
    InterestBuilder::new(group.clone().append_component(keyword(b"signal")))
        .lifetime(std::time::Duration::from_secs(1))
        .hop_limit(8)
        .app_parameters(packet.to_vec())
        .build()
}

/// The group a push Interest `wire` was sent into and the packet it carries, if it is a push
/// Interest: a name `<group>/32=signal/<digest>` and ApplicationParameters.
pub fn pushed(wire: &Bytes) -> Option<(Name, Bytes)> {
    let interest = Interest::decode(wire.clone()).ok()?;
    let comps = interest.name.components();
    let n = comps.len().checked_sub(2)?;
    if comps[n] != keyword(b"signal") {
        return None;
    }
    let group = Name::from_components(comps[..n].iter().cloned());
    Some((group, interest.app_parameters()?.clone()))
}

/// Whether `name` has a `32=signal` component.
pub fn names_signal(name: &Name) -> bool {
    name.components().iter().any(|c| *c == keyword(b"signal"))
}

fn keyword(value: &'static [u8]) -> ndn_packet::NameComponent {
    ndn_packet::NameComponent::new(KEYWORD, Bytes::from_static(value))
}

fn aad(key_id: &[u8; 8]) -> Vec<u8> {
    let mut aad = CONTEXT.to_vec();
    aad.extend_from_slice(key_id);
    aad
}

/// A NonNegativeInteger, shortest of 1, 2, 4 or 8 octets.
fn nni(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    match v {
        0..=0xFF => be[7..].to_vec(),
        0x100..=0xFFFF => be[6..].to_vec(),
        0x1_0000..=0xFFFF_FFFF => be[4..].to_vec(),
        _ => be.to_vec(),
    }
}

fn from_nni(v: &[u8]) -> Option<u64> {
    matches!(v.len(), 1 | 2 | 4 | 8).then(|| v.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
}

/// Append the TLV `typ`, `value` to `out`.
fn tlv(out: &mut Vec<u8>, typ: u64, value: &[u8]) {
    varnum(out, typ);
    varnum(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn varnum(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=252 => out.push(v as u8),
        253..=0xFFFF => {
            out.push(253);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(254);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// The TLV at the start of `bytes`: its type, its value and what follows it.
fn read(bytes: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (typ, rest) = read_varnum(bytes)?;
    let (len, rest) = read_varnum(rest)?;
    let len = usize::try_from(len).ok()?;
    (rest.len() >= len).then(|| (typ, &rest[..len], &rest[len..]))
}

fn read_varnum(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    let width = match first {
        0..=252 => return Some((u64::from(first), rest)),
        253 => 2,
        254 => 4,
        255 => 8,
    };
    let raw = rest.get(..width)?;
    Some((
        raw.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)),
        &rest[width..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// What `body` signs, `parse_body` reads back, and what `seal` seals, `sealed` and `open`
    /// read back; a seal opens under its own key only.
    #[test]
    fn a_body_and_its_seal_read_back() {
        let key = RunKey::from_seed([7; 32]);
        let scope = n("/alice/32=data/notes");
        let header = header_content(&key.public(), 1_000_000, 2_000);
        assert_eq!(header_run_key(&header), Some(key.public()));
        let signals = [Signal {
            seq: 1_000_000,
            address: Bytes::from_static(b"cursor"),
            expires: 1_234,
            payload: Bytes::from_static(b"17,42"),
        }];
        let wire = body(&scope, &key.id(), Some(&header), &signals, &key);
        let read = parse_body(&wire).unwrap();
        assert_eq!(
            (read.digest, read.run, read.header, read.signals),
            (
                scope_digest(&scope),
                key.id(),
                Some(header),
                signals.to_vec()
            )
        );
        assert_eq!(read.signature.len(), 64);

        let packet = seal(&[1; 8], &[2; 32], &[3; 24], &wire);
        let s = sealed(&packet).unwrap();
        assert_eq!((s.key_id, s.nonce), ([1; 8], [3; 24]));
        assert_eq!(open(&s, &[2; 32]).as_deref(), Some(&wire[..]));
        assert_eq!(open(&s, &[4; 32]), None);
        // A padded plaintext (the hub pads sealed packets to a size bucket) opens to its body.
        let mut padded = wire.to_vec();
        tlv(&mut padded, SIGNAL_PADDING, &[0; 40]);
        let s = sealed(&seal(&[1; 8], &[2; 32], &[3; 24], &padded)).unwrap();
        assert_eq!(open(&s, &[2; 32]).as_deref(), Some(&wire[..]));
    }

    /// The push Interest names the group, `32=signal` and the parameters digest, and carries the
    /// packet: `pushed` reads both back.
    #[test]
    fn a_push_names_its_group_and_carries_the_packet() {
        let group = n("/alice/32=sync");
        let wire = push(&group, b"packet");
        let (g, packet) = pushed(&wire).unwrap();
        assert_eq!((g, &packet[..]), (group, &b"packet"[..]));
        let interest = Interest::decode(wire).unwrap();
        assert!(names_signal(&interest.name));
        assert_eq!(interest.name.len(), 4);
    }
}
