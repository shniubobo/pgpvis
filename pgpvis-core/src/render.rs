use chrono::{DateTime, SecondsFormat};
use serde::Serialize;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::packet::*;

/// Represents a node in the tree of packets with rendered text, along with
/// [`Span`] information and child nodes.
///
/// For [`Node`]s passed across the wasm boundary, this most probably
/// represents one complete packet.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Node {
    /// Span information for the node. [`None`] if not applicable.
    pub(crate) span: Option<Span<()>>,

    /// Text to be displayed for the node.
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub text: String,

    /// Children nodes.
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub children: Vec<Node>,
}

#[wasm_bindgen]
impl Node {
    /// Offset of the node's span. [`None`] if not applicable.
    #[wasm_bindgen(getter)]
    pub fn offset(&self) -> Option<usize> {
        self.span.as_ref().map(|span| span.offset)
    }

    /// Length of the node's span. [`None`] if not applicable.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> Option<usize> {
        self.span.as_ref().map(|span| span.length)
    }
}

impl Node {
    pub fn render(packets: PacketSequence) -> Vec<Self> {
        packets.0.iter().map(|packet| packet.render()).collect()
    }

    fn with_text(text: String) -> Self {
        Self {
            span: None,
            text,
            children: vec![],
        }
    }
}

/// A [`Node`] without [`Node::span`] and [`Node::text`].
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize)]
struct RootlessNode {
    pub children: Vec<Node>,
}

/// Trait implemented by types that can be rendered into a [`Node`].
///
/// There are two [`Render`]-related traits, one being [`Render`] itself and
/// the other being [`RenderRootlessly`]. This is so designed that:
///
/// 1. For any type that is implementing [`Render`], if it wants to
///    [`extend`](Vec::extend) its [`Node`] with its
///    [`children`](Node::children)'s [`children`](Node::children) (thus
///    discarding the children's root), it should explicitly call
///    [`RenderRootlessly::render_rootlessly`];
///
/// 2. For any type that has no [`Span`] information, it should implement
///    [`RenderRootlessly`] and not [`Render`];
///
/// 3. And as a result, no root [`Node`] will be accidentally discarded during
///    [`extend`](Vec::extend)ing.
///
/// This is not entirely foolproof though, for one could still implement
/// [`Render`] when they should instead implement [`RenderRootlessly`], and
/// vice versa. However, this ensures that the correct method is called once
/// every trait is implemented correctly. One way to address this issue is to
/// probihit `impl<T> RenderRootlessly for Span<T>` and only allow [`Render`]
/// to be implemented for `Span<T>`, but this is not easy, if not impossible.
/// One effort having been made is `impl<T> RenderRootlessly for Span<T>` with
/// [`unimplemented!`], so any other `impl<T> RenderRootlessly for Span<T>` or
/// for a specialized `T` will cause a conflict.
///
/// We could instead make [`Node`] an enum with a rooted and a rootless
/// variant, and merge the two traits to return that enum. However, that would
/// require a lot of `if let`s or `match`es, which is quite awkward.
///
/// We could also extract [`Node::span`] and [`Node::text`] into another struct
/// (say `Root`), and store `Option<Root>` in [`Node`]s, but this does not
/// prevent discarding the root [`Node`] ([`None`] will not be mistaken for
/// [`Some`], i.e. rootlessly rendered nodes will not be mistaken for nodes
/// with a root; [`Some`] values may, however, be ignored, i.e. the root node
/// is discarded).
trait Render {
    // Notation used in comments on `render` or `render_rootlessly` impls:
    //
    // - No notation: verbatim
    // - `[]`: description of what is here
    // - `[[]]`: square brackets
    // - `&[]`: not rendered by this function, but delegated to children
    // - `**`: non-existing node
    // - `->`: provided by children but modified here
    //
    // Each level is expressed by indentation of two whitespaces.
    fn render(&self) -> Node;
}

/// Trait implemented by types that can be rendered into a [`RootlessNode`].
///
/// See also documentation on [`Render`] for more information.
trait RenderRootlessly {
    // See also comments on `Render::render` for more information.
    fn render_rootlessly(&self) -> RootlessNode;
}

impl<T> Span<T> {
    fn to_node(&self, text: String) -> Node {
        Node {
            span: Some(Span::new(self.offset, self.length, ())),
            text,
            children: vec![],
        }
    }
}

impl<T> RenderRootlessly for Span<T> {
    fn render_rootlessly(&self) -> RootlessNode {
        unimplemented!("`RenderRootlessly` should not be implemented for `Span<T>`")
    }
}

macro_rules! render_packet {
    ($node:ident, $packet:ident) => {
        $node.children = vec![$packet.header.render(), $packet.body.render()]
    };
}

impl Render for Span<AnyPacket> {
    // [Summary line]
    //   &[Header]
    //   &[Body]
    fn render(&self) -> Node {
        let mut node = self.to_node(self.inner.to_string());

        match &self.inner {
            AnyPacket::Reserved(packet) => render_packet!(node, packet),
            AnyPacket::PublicKey(packet) => render_packet!(node, packet),
            AnyPacket::UserId(packet) => render_packet!(node, packet),
            AnyPacket::PublicSubkey(packet) => render_packet!(node, packet),
            AnyPacket::Private60(packet) => render_packet!(node, packet),
            AnyPacket::Unimplemented => (),
        }

        node
    }
}

impl<T> Render for Span<Header<T>>
where
    T: PacketType,
{
    // Header
    //   &[CTB]
    //   &[Length]
    fn render(&self) -> Node {
        let mut node = self.to_node("Header".to_string());

        match &self.inner {
            Header::OpenPgp { ctb, length } => {
                node.children = vec![ctb.render(), length.render()];
            }
            Header::Legacy { ctb, length } => {
                node.children = vec![ctb.render(), length.render()];
            }
        }

        node
    }
}

impl<T> Render for Span<OpenPgpCtb<T>>
where
    T: PacketType,
{
    // CTB
    //   Format: OpenPGP
    //   Type ID: [Type ID]
    fn render(&self) -> Node {
        let mut node = self.to_node("CTB".to_string());

        node.children = vec![
            Node::with_text("Format: OpenPGP".to_string()),
            Node::with_text(format!("Type ID: {}", T::TYPE_ID)),
        ];

        node
    }
}

impl<T> Render for Span<LegacyCtb<T>>
where
    T: PacketType,
{
    // CTB
    //   Format: Legacy
    //   Type ID: [Type ID]
    fn render(&self) -> Node {
        let mut node = self.to_node("CTB".to_string());

        node.children = vec![
            Node::with_text("Format: Legacy".to_string()),
            Node::with_text(format!("Type ID: {}", T::TYPE_ID)),
        ];

        node
    }
}

impl Render for Span<OpenPgpLength> {
    // Length: [length] (Full)
    // OR
    // Length: [length] (Partial)
    fn render(&self) -> Node {
        match &self.inner {
            OpenPgpLength::Full(length) => self.to_node(format!("Length: {length} (Full)")),
            OpenPgpLength::Partial(length) => self.to_node(format!("Length: {length} (Partial)")),
        }
    }
}

impl Render for Span<LegacyLength> {
    // Length: [length] (Full)
    // OR
    // Length: Indeterminate
    fn render(&self) -> Node {
        match &self.inner {
            LegacyLength::Full(length) => self.to_node(format!("Length: {length} (Full)")),
            LegacyLength::Indeterminate => self.to_node("Length: Indeterminate".to_string()),
        }
    }
}

impl<T> Render for Span<Body<T>>
where
    T: PacketType + RenderRootlessly,
{
    // Body
    //   &[Body]
    fn render(&self) -> Node {
        let mut node = self.to_node("Body".to_string());
        node.children
            .extend(self.inner.0.render_rootlessly().children);
        node
    }
}

impl RenderRootlessly for PublicKey {
    // *No root node*
    //   &[Body]
    fn render_rootlessly(&self) -> RootlessNode {
        match &self {
            Self::Version4RsaEncryptSign(inner) => inner.render_rootlessly(),
            Self::Version4EdDsaLegacy(inner) => inner.render_rootlessly(),
            Self::Version4Ed25519(inner) => inner.render_rootlessly(),
            Self::Version4Unimplemented(inner) => inner.render_rootlessly(),
        }
    }
}

impl RenderRootlessly for PublicSubkey {
    // *No root node*
    //   &[Body]
    fn render_rootlessly(&self) -> RootlessNode {
        match &self {
            Self::Version4RsaEncryptSign(inner) => inner.render_rootlessly(),
            Self::Version4EdDsaLegacy(inner) => inner.render_rootlessly(),
            Self::Version4Ed25519(inner) => inner.render_rootlessly(),
            Self::Version4Unimplemented(inner) => inner.render_rootlessly(),
        }
    }
}

impl<R, A> RenderRootlessly for PublicVersion4<R, A>
where
    R: KeyRole,
    A: PublicKeyAlgorithm + RenderRootlessly,
{
    // *No root node*
    //   Version: 4
    //   Creation Time: [ISO creation time] ([UNIX timestamp])
    //   Algorithm: [algorithm]
    //   Key Material
    //     &[Key Material]
    fn render_rootlessly(&self) -> RootlessNode {
        RootlessNode {
            children: vec![
                self.render_version(),
                self.render_creation_time(),
                self.render_algorithm(),
                self.render_key_material(),
            ],
        }
    }
}

#[expect(private_bounds)]
impl<R, A> PublicVersion4<R, A>
where
    R: KeyRole,
    A: PublicKeyAlgorithm + RenderRootlessly,
{
    fn render_version(&self) -> Node {
        self.version.to_node("Version: 4".to_string())
    }

    fn render_creation_time(&self) -> Node {
        let timestamp = self.creation_time.inner.0;
        let date_time = DateTime::from_timestamp(timestamp.into(), 0)
            .expect("`packet::Time` should only contain valid UNIX timestamp");
        let text = format!(
            "Creation Time: {} ({})",
            date_time.to_rfc3339_opts(SecondsFormat::Secs, true),
            timestamp
        );
        self.creation_time.to_node(text)
    }

    fn render_algorithm(&self) -> Node {
        self.algorithm
            .to_node(format!("Algorithm: {}", self.key_material.inner))
    }

    fn render_key_material(&self) -> Node {
        let mut node = self.key_material.to_node("Key Material".to_string());
        node.children
            .extend(self.key_material.inner.render_rootlessly().children);
        node
    }
}

impl RenderRootlessly for RsaEncryptSign {
    // *No root node*
    //   &[MPI] -> n (MPI)
    //   &[MPI] -> e (MPI)
    fn render_rootlessly(&self) -> RootlessNode {
        let mut n = self.n.render();
        n.text = "n (MPI)".to_string();
        let mut e = self.e.render();
        e.text = "e (MPI)".to_string();
        RootlessNode {
            children: vec![n, e],
        }
    }
}

impl RenderRootlessly for EdDsaLegacy {
    // *No root node*
    //   &[Curve OID]
    //   &[MPI] -> Q (MPI)
    fn render_rootlessly(&self) -> RootlessNode {
        let curve_oid = self.curve_oid.render();
        let mut q = self.q.render();
        q.text = "Q (MPI)".to_string();
        RootlessNode {
            children: vec![curve_oid, q],
        }
    }
}

impl RenderRootlessly for X25519 {
    // *No root node*
    //   [[32 octets]]
    fn render_rootlessly(&self) -> RootlessNode {
        RootlessNode {
            // Always 32, could be hard-coded.
            children: vec![self.0.to_node(format!("[{} octets]", self.0.inner.len()))],
        }
    }
}

impl RenderRootlessly for Ed25519 {
    // *No root node*
    //   [[32 octets]]
    fn render_rootlessly(&self) -> RootlessNode {
        RootlessNode {
            // Always 32, could be hard-coded.
            children: vec![self.0.to_node(format!("[{} octets]", self.0.inner.len()))],
        }
    }
}

impl RenderRootlessly for UnimplementedPublicKeyAlgorithm {
    // *No root node*
    //   Unimplemented
    fn render_rootlessly(&self) -> RootlessNode {
        RootlessNode {
            children: vec![Node::with_text("Unimplemented".to_string())],
        }
    }
}

impl Render for Span<Mpi> {
    // MPI
    //   Length: [length]
    //   Integers: [[[length] octets]]
    fn render(&self) -> Node {
        // We could avoid setting `text`, as it will always be overwriten by
        // the parent node.
        let mut node = self.to_node("MPI".to_string());
        node.children = vec![self.render_length(), self.render_integers()];
        node
    }
}

impl Span<Mpi> {
    fn render_length(&self) -> Node {
        let length = &self.inner.length;
        length.to_node(format!("Length: {}", length.inner))
    }

    fn render_integers(&self) -> Node {
        let integers = &self.inner.integers;
        integers.to_node(format!("Integers: [{} octets]", integers.inner.len()))
    }
}

impl Render for Span<CurveOid> {
    // Curve OID
    //   Name: [name]
    //   Length: [length]
    //   OID: [[[length] octets]]
    fn render(&self) -> Node {
        let mut node = self.to_node("Curve OID".to_string());
        node.children = vec![self.render_name(), self.render_length(), self.render_oid()];
        node
    }
}

impl Span<CurveOid> {
    fn render_name(&self) -> Node {
        Node::with_text(format!("Name: {}", self.inner.name))
    }

    fn render_length(&self) -> Node {
        let length = &self.inner.length;
        length.to_node(format!("Length: {}", length.inner))
    }

    fn render_oid(&self) -> Node {
        let oid = &self.inner.oid;
        oid.to_node(format!("OID: [{} octets]", oid.inner.len()))
    }
}

impl RenderRootlessly for UserId {
    // *No root node*
    //   User ID: [User ID]
    fn render_rootlessly(&self) -> RootlessNode {
        RootlessNode {
            children: vec![self
                .user_id
                .to_node(format!("User ID: {}", self.user_id.inner))],
        }
    }
}

macro_rules! gen_impl_render_for_undefined_packets {
    { $( $packet_type:ident => $text:literal ),+ $(,)? } => {
        $(
            impl RenderRootlessly for $packet_type {
                // *No root node*
                //   [$text]
                fn render_rootlessly(&self) -> RootlessNode {
                    RootlessNode {
                        children: vec![Node::with_text($text.to_string())],
                    }
                }
            }
        )+
    };
}

gen_impl_render_for_undefined_packets! {
    Reserved => "Reserved",
    Private60 => "Private",
}

#[cfg(test)]
mod tests {
    //! To check snapshots in this module:
    //!
    //! 1. Check all spans are present, by counting the number of `spans.next`
    //!    calls, multiplying it by 2, and checking 0..[result of calculation]
    //!    are all present in the snapshot;
    //!
    //! 2. Check the text is correct by looking at comments on each `render` or
    //!    `render_rootlessly` implementations.

    use std::cell::RefCell;

    use super::*;

    /// Make an assertion using [`insta::assert_yaml_snapshot!`], saving snapshots
    /// in `{crate_root}/tests/snapshots`.
    macro_rules! insta_assert {
        ($value:ident) => {
            let crate_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let snapshot_path = crate_root.join("tests/snapshots");
            insta::with_settings!({snapshot_path => snapshot_path}, {
                insta::assert_yaml_snapshot!($value);
            });
        };
    }

    /// Used to construct [`Span`]s with self-incrementing [`Span::offset`]s
    /// and [`Span::length`]s.
    ///
    /// The [`RefCell`] is necessary because the compiler cannot make sure
    /// only one mutable reference of `self` is alive when calling
    /// [`Self::next`] during nested construction of [`packet`](crate::packet)
    /// types, if [`Self::next`]'s receiver is `&mut self`.
    struct SelfIncrementingDummySpan(RefCell<usize>);
    impl SelfIncrementingDummySpan {
        pub fn new() -> Self {
            Self(RefCell::new(0))
        }

        // Able to be called multiple times during struct construction.
        // See https://stackoverflow.com/q/61984925
        pub fn next<T>(&self, inner: T) -> Span<T> {
            let span = Span {
                offset: *self.0.borrow(),
                length: *self.0.borrow() + 1,
                inner,
            };
            *self.0.borrow_mut() += 2;
            span
        }
    }

    #[test]
    fn any_packet() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(AnyPacket::UserId(Packet {
            header: spans.next(Header::OpenPgp {
                ctb: spans.next(OpenPgpCtb(Ctb::default())),
                length: spans.next(OpenPgpLength::Full(1)),
            }),
            body: spans.next(Body(UserId {
                user_id: spans.next("a".to_string()),
            })),
        }));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn any_packet_unknown() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(AnyPacket::Unimplemented);

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn header_openpgp() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(Header::OpenPgp {
            ctb: spans.next(OpenPgpCtb::<UserId>(Ctb::default())),
            length: spans.next(OpenPgpLength::Full(123)),
        });

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn header_legacy() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(Header::Legacy {
            ctb: spans.next(LegacyCtb::<UserId>(Ctb::default())),
            length: spans.next(LegacyLength::Full(123)),
        });

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn openpgp_ctb() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(OpenPgpCtb::<UserId>(Ctb::default()));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn legecy_ctb() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(LegacyCtb::<UserId>(Ctb::default()));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn openpgp_length_full() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(OpenPgpLength::Full(123));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn openpgp_length_partial() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(OpenPgpLength::Partial(512));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn legacy_length_full() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(LegacyLength::Full(123));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn legacy_length_indeterminate() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(LegacyLength::Indeterminate);

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn body() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(Body(UserId {
            user_id: spans.next("a".to_string()),
        }));

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn public_key() {
        let spans = SelfIncrementingDummySpan::new();

        let node = PublicKey::Version4Ed25519(PublicVersion4 {
            role: Key,
            version: spans.next(()),
            creation_time: spans.next(Time(0)),
            algorithm: spans.next(()),
            key_material: spans.next(Ed25519(spans.next([0; 32]))),
            key_id: "DEADBEEFDEADBEEF".to_string(),
        });

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn public_subkey() {
        let spans = SelfIncrementingDummySpan::new();

        let node = PublicSubkey::Version4Ed25519(PublicVersion4 {
            role: Subkey,
            version: spans.next(()),
            creation_time: spans.next(Time(0)),
            algorithm: spans.next(()),
            key_material: spans.next(Ed25519(spans.next([0; 32]))),
            key_id: "DEADBEEFDEADBEEF".to_string(),
        });

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn public_version_4_rsa_encrypt_sign() {
        let spans = SelfIncrementingDummySpan::new();

        let node = PublicVersion4 {
            role: Key,
            version: spans.next(()),
            creation_time: spans.next(Time(0)),
            algorithm: spans.next(()),
            key_material: spans.next(RsaEncryptSign {
                n: spans.next(Mpi {
                    length: spans.next(1),
                    integers: spans.next(vec![0; 2]),
                }),
                e: spans.next(Mpi {
                    length: spans.next(1),
                    integers: spans.next(vec![0; 2]),
                }),
            }),
            key_id: "DEADBEEFDEADBEEF".to_string(),
        };

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn public_version_4_ed25519() {
        let spans = SelfIncrementingDummySpan::new();

        let node = PublicVersion4 {
            role: Key,
            version: spans.next(()),
            creation_time: spans.next(Time(0)),
            algorithm: spans.next(()),
            key_material: spans.next(Ed25519(spans.next([0; 32]))),
            key_id: "DEADBEEFDEADBEEF".to_string(),
        };

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn rsa_encrypt_sign() {
        let spans = SelfIncrementingDummySpan::new();

        let node = RsaEncryptSign {
            n: spans.next(Mpi {
                length: spans.next(1),
                integers: spans.next(vec![0; 2]),
            }),
            e: spans.next(Mpi {
                length: spans.next(1),
                integers: spans.next(vec![0; 2]),
            }),
        };

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn eddsa_legacy() {
        let spans = SelfIncrementingDummySpan::new();

        let node = EdDsaLegacy {
            curve_oid: spans.next(CurveOid {
                name: CurveName::Ed25519Legacy,
                length: spans.next(1),
                oid: spans.next(vec![0; 2]),
            }),
            q: spans.next(Mpi {
                length: spans.next(1),
                integers: spans.next(vec![0; 2]),
            }),
        };

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn x25519() {
        let spans = SelfIncrementingDummySpan::new();

        let node = X25519(spans.next([0; 32]));

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn ed25519() {
        let spans = SelfIncrementingDummySpan::new();

        let node = Ed25519(spans.next([0; 32]));

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn unimplemented_public_key_algorithm() {
        let node = UnimplementedPublicKeyAlgorithm.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn mpi() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(Mpi {
            length: spans.next(1),
            integers: spans.next(vec![0; 2]),
        });

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn curve_oid() {
        let spans = SelfIncrementingDummySpan::new();

        let node = spans.next(CurveOid {
            name: CurveName::Ed25519Legacy,
            length: spans.next(1),
            oid: spans.next(vec![0; 2]),
        });

        let node = node.render();
        insta_assert!(node);
    }

    #[test]
    fn user_id() {
        let spans = SelfIncrementingDummySpan::new();

        let node = UserId {
            user_id: spans.next("a".to_string()),
        };

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    // For undefined packet types, only one test is written for each category,
    // since they are generated using a macro, and the correctness of one test
    // means correctness of the whole category.

    #[test]
    fn reserved() {
        let node = Reserved;

        let node = node.render_rootlessly();
        insta_assert!(node);
    }

    #[test]
    fn private() {
        let node = Private60;

        let node = node.render_rootlessly();
        insta_assert!(node);
    }
}
