//! pHash-64 parity: the frame pHash reimplemented in this crate (no
//! `pith-math` edge) must produce the *identical* `u64` as
//! `pith_image::phash::image_phash` — the suite's image-lane oracle —
//! on the same luma planes. Byte-compatibility of the two pipelines
//! (box_average → DCT → lower-middle median threshold) is part of the
//! suite contract, so this pin lives beside the fixtures it guards.
//! The upstream kit pins the same equality in its facade tests.

use pith_image::raster::{Gray, Image};
use pith_video::frame_phash;

/// A deterministic non-trivial luma plane through both pipelines.
#[test]
fn video_frame_phash_matches_image_phash() {
    let mut rng = pith_digest::SplitMix64::new(0xA11);
    let plane: Vec<u8> = (0..64 * 48).map(|_| rng.next_u64() as u8).collect();
    let img = Image::<Gray, u8>::from_vec(64, 48, plane.clone()).unwrap();
    assert_eq!(
        frame_phash(64, 48, &plane).unwrap(),
        pith_image::phash::image_phash(&img).unwrap()
    );
    // A second shape: gradient instead of noise.
    let plane: Vec<u8> = (0..32 * 24).map(|i| ((i * 7) % 256) as u8).collect();
    let img = Image::<Gray, u8>::from_vec(32, 24, plane.clone()).unwrap();
    assert_eq!(
        frame_phash(32, 24, &plane).unwrap(),
        pith_image::phash::image_phash(&img).unwrap()
    );
}

/// Flat, all-black and all-white planes agree across the lanes too —
/// the degenerate DCT (DC-only) must threshold identically everywhere.
#[test]
fn degenerate_planes_match_image_phash() {
    for fill in [0u8, 128, 255] {
        let plane = vec![fill; 16 * 16];
        let img = Image::<Gray, u8>::from_vec(16, 16, plane.clone()).unwrap();
        assert_eq!(
            frame_phash(16, 16, &plane).unwrap(),
            pith_image::phash::image_phash(&img).unwrap(),
            "fill {fill} diverged between the two pHash pipelines"
        );
    }
}
