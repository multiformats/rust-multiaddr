//! helper types

use libp2p_identity::PeerId;

/// `PeerId` doesn't `impl quickcheck::Arbitrary` so this newtype is useful beyond this crate for the similar purposes.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PId(pub PeerId);

impl quickcheck::Arbitrary for PId {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut hash: [u8; 32] = [0; 32];
        hash.fill_with(|| u8::arbitrary(g));

        PId(PeerId::from_multihash(
            multihash::Multihash::wrap(0x0, &hash).expect("The digest size is never too large"),
        )
        .expect("identity multihash works if digest size < 64"))
    }
}

/// ASCII string without '/'
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SubString(pub String);

impl quickcheck::Arbitrary for SubString {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut s = String::arbitrary(g);
        s.retain(|c| c.is_ascii() && c != '/');
        SubString(s)
    }
}
