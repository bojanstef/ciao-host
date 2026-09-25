//! Release archive signatures (ROADMAP "Pre-launch distribution security", item 1).
//!
//! Every archive on the channel carries `<archive>.sig`, an OpenSSH signature
//! (`ssh-keygen -Y sign -n ciao-release`) made in the release workflow with a key that lives in
//! neither the bucket nor the site. The `.sha256` beside an archive comes from the same place the
//! archive does, so it proves only that the download is whole; this proves who built it.
//! `install.sh` checks the same signature with `ssh-keygen -Y verify`. This is the binary's half,
//! so `ciao install` and `ciao update` never fall back to the checksum alone.
//!
//! The format is OpenSSH's PROTOCOL.sshsig, parsed here directly rather than by shelling out: a
//! host without `ssh-keygen` still updates, and nothing about the check depends on its version.
//!
//! Releases published before signing began (0.1.53 and earlier) carry no `.sig`, so a binary with
//! this check refuses to install one. `ciao install --rollback` swaps the local slot and is
//! unaffected.

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};

/// The public half of the release signing key. One owner: `scripts/release-signing.pub`.
/// `install.sh` is served standalone, so it embeds the same line; a test below fences the two.
pub const RELEASE_SIGNING_KEY: &str = include_str!("../../../scripts/release-signing.pub");
pub const SIGNING_NAMESPACE: &str = "ciao-release";
/// An ed25519 SSHSIG is about 300 bytes armored; anything near this is not one.
pub const MAX_SIGNATURE_BYTES: u64 = 4 * 1024;

const MAGIC: &[u8] = b"SSHSIG";
const KEY_TYPE: &[u8] = b"ssh-ed25519";
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----";

pub fn signature_file_name(archive: &str) -> String {
    format!("{archive}.sig")
}

/// Verifies `armored` as the release key's signature over `data`.
pub fn verify_release_signature(data: &[u8], armored: &[u8]) -> Result<()> {
    verify_signed_by(data, armored, RELEASE_SIGNING_KEY)
}

/// The check itself, against any trusted `ssh-ed25519 <base64> [comment]` line, so tests can use
/// their own key. Everything that is not a good signature from exactly that key, in exactly the
/// release namespace, is one refusal: telling a forger which part failed helps no one else.
pub(crate) fn verify_signed_by(data: &[u8], armored: &[u8], trusted_key_line: &str) -> Result<()> {
    let trusted = public_key_from_line(trusted_key_line)
        .ok_or_else(|| anyhow!("the embedded release signing key is malformed"))?;
    let refused = || anyhow!("the release signature does not verify against Ciao's release key");
    let blob = dearmor(armored).ok_or_else(refused)?;
    let mut reader = WireReader(&blob);
    if reader.take(MAGIC.len()) != Some(MAGIC) || reader.u32() != Some(1) {
        bail!(refused());
    }
    let key = reader
        .string()
        .and_then(ed25519_public_key)
        .ok_or_else(refused)?;
    let namespace = reader.string().ok_or_else(refused)?;
    let reserved = reader.string().ok_or_else(refused)?;
    let hash_algorithm = reader.string().ok_or_else(refused)?;
    let signature = reader
        .string()
        .and_then(ed25519_signature)
        .ok_or_else(refused)?;
    if !reader.0.is_empty() || key != trusted || namespace != SIGNING_NAMESPACE.as_bytes() {
        bail!(refused());
    }
    let digest = match hash_algorithm {
        b"sha512" => Sha512::digest(data).to_vec(),
        b"sha256" => Sha256::digest(data).to_vec(),
        _ => bail!(refused()),
    };
    let mut signed = MAGIC.to_vec();
    for field in [namespace, reserved, hash_algorithm, &digest] {
        put_string(&mut signed, field);
    }
    let key = iroh::PublicKey::from_bytes(&key).map_err(|_| refused())?;
    key.verify(&signed, &iroh::Signature::from_bytes(&signature))
        .map_err(|_| refused())
}

fn dearmor(armored: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(armored).ok()?.trim();
    let body = text.strip_prefix(ARMOR_BEGIN)?.strip_suffix(ARMOR_END)?;
    let joined: String = body.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(joined)
        .ok()
}

fn public_key_from_line(line: &str) -> Option<[u8; 32]> {
    let mut fields = line.split_whitespace();
    if fields.next()? != "ssh-ed25519" {
        return None;
    }
    let wire = base64::engine::general_purpose::STANDARD
        .decode(fields.next()?)
        .ok()?;
    ed25519_public_key(&wire)
}

/// `string "ssh-ed25519" || string key[32]`, and nothing after it.
fn ed25519_public_key(wire: &[u8]) -> Option<[u8; 32]> {
    let mut reader = WireReader(wire);
    (reader.string()? == KEY_TYPE).then_some(())?;
    let key = reader.string()?.try_into().ok()?;
    reader.0.is_empty().then_some(key)
}

/// `string "ssh-ed25519" || string signature[64]`, and nothing after it.
fn ed25519_signature(wire: &[u8]) -> Option<[u8; 64]> {
    let mut reader = WireReader(wire);
    (reader.string()? == KEY_TYPE).then_some(())?;
    let signature = reader.string()?.try_into().ok()?;
    reader.0.is_empty().then_some(signature)
}

fn put_string(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// SSH wire-format reads (RFC 4251 §5); every read is bounded by what is left.
struct WireReader<'a>(&'a [u8]);

impl<'a> WireReader<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        self.take(length)
    }
}

/// Test-only signer producing exactly what `ssh-keygen -Y sign` writes, so installer tests can sign
/// archives they build on the fly. The committed fixtures below prove the verifier accepts real
/// `ssh-keygen` output; this only saves each test from needing the tool.
#[cfg(test)]
pub(crate) mod test_signer {
    use super::*;

    pub(crate) struct TestKey(iroh::SecretKey);

    impl TestKey {
        pub(crate) fn new(seed: u8) -> Self {
            Self(iroh::SecretKey::from_bytes(&[seed; 32]))
        }

        pub(crate) fn public_line(&self) -> String {
            let mut wire = Vec::new();
            put_string(&mut wire, KEY_TYPE);
            put_string(&mut wire, self.0.public().as_bytes());
            format!(
                "ssh-ed25519 {} test@ciao",
                base64::engine::general_purpose::STANDARD.encode(wire)
            )
        }

        pub(crate) fn sign(&self, data: &[u8], namespace: &str) -> Vec<u8> {
            let digest = Sha512::digest(data);
            let mut signed = MAGIC.to_vec();
            for field in [namespace.as_bytes(), b"", b"sha512", &digest] {
                put_string(&mut signed, field);
            }
            let signature = self.0.sign(&signed).to_bytes();
            let (mut key_wire, mut signature_wire) = (Vec::new(), Vec::new());
            put_string(&mut key_wire, KEY_TYPE);
            put_string(&mut key_wire, self.0.public().as_bytes());
            put_string(&mut signature_wire, KEY_TYPE);
            put_string(&mut signature_wire, &signature);
            let mut blob = MAGIC.to_vec();
            blob.extend_from_slice(&1u32.to_be_bytes());
            for field in [
                &key_wire[..],
                namespace.as_bytes(),
                b"",
                b"sha512",
                &signature_wire,
            ] {
                put_string(&mut blob, field);
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
            let lines: Vec<&str> = encoded
                .as_bytes()
                .chunks(70)
                .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ascii"))
                .collect();
            format!("{ARMOR_BEGIN}\n{}\n{ARMOR_END}\n", lines.join("\n")).into_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_signer::TestKey, *};

    // Made by `ssh-keygen -Y sign` (OpenSSH 10.2) with a throwaway key whose private half was
    // deleted; `wrong-key.sig` is a second throwaway key, `wrong-namespace.sig` used `-n file`.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/release-signing/"
    );

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURE}{name}")).expect("fixture")
    }

    fn fixture_key() -> String {
        String::from_utf8(fixture("test.pub")).unwrap()
    }

    #[test]
    fn a_real_ssh_keygen_signature_verifies_and_every_variation_of_it_is_refused() {
        let data = fixture("archive.bin");
        let key = fixture_key();
        verify_signed_by(&data, &fixture("archive.bin.sig"), &key).expect("ssh-keygen output");

        let mut tampered = data.clone();
        tampered[0] ^= 1;
        let signature = fixture("archive.bin.sig");
        let truncated = &signature[..signature.len() / 2];
        let other_key = TestKey::new(9).public_line();
        let cases: [(&str, &[u8], &[u8], &str); 6] = [
            ("tampered archive", &tampered, &signature, &key),
            (
                "another key's signature",
                &data,
                &fixture("wrong-key.sig"),
                &key,
            ),
            (
                "the file namespace",
                &data,
                &fixture("wrong-namespace.sig"),
                &key,
            ),
            (
                "a key the signature is not from",
                &data,
                &signature,
                &other_key,
            ),
            ("truncated armor", &data, truncated, &key),
            ("garbage", &data, b"not a signature at all", &key),
        ];
        for (case, data, signature, key) in cases {
            let error = verify_signed_by(data, signature, key).expect_err(case);
            assert!(
                error.to_string().contains("does not verify"),
                "{case}: {error}"
            );
        }
    }

    #[test]
    fn the_test_signer_writes_what_the_verifier_reads() {
        let key = TestKey::new(7);
        let signature = key.sign(b"archive", SIGNING_NAMESPACE);
        verify_signed_by(b"archive", &signature, &key.public_line()).unwrap();
        assert!(
            verify_signed_by(
                b"archive",
                &key.sign(b"archive", "file"),
                &key.public_line()
            )
            .is_err()
        );
        // Byte-identical in shape to the ssh-keygen fixture: same armor, same line width.
        let text = String::from_utf8(signature).unwrap();
        let fixture = String::from_utf8(fixture("archive.bin.sig")).unwrap();
        assert_eq!(
            text.lines().map(str::len).collect::<Vec<_>>(),
            fixture.lines().map(str::len).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_embedded_key_is_one_ed25519_line_and_install_sh_carries_the_same_one() {
        let line = RELEASE_SIGNING_KEY.trim();
        assert_eq!(RELEASE_SIGNING_KEY.lines().count(), 1);
        assert!(public_key_from_line(line).is_some(), "{line}");
        assert!(line.ends_with(" release@ciaooo.app"));
        let install_sh = include_str!("../../../scripts/install.sh");
        let literal = format!("RELEASE_SIGNING_KEY='{line}'");
        assert_eq!(
            install_sh.matches(&literal).count(),
            1,
            "install.sh must embed scripts/release-signing.pub verbatim"
        );
        assert_eq!(install_sh.matches("RELEASE_SIGNING_KEY='").count(), 1);
    }
}
