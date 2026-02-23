// These tests take too long for miri
#![cfg(not(miri))]
use std::path::Path;

use crate::rsp::KatSet;

mod rsp;

#[test]
fn test_small_vectors() {
    let kat_set = KatSet::load(Path::new(
        "tests/test-vectors/byte-oriented/SHA3_384ShortMsg.rsp",
    ));
    assert_eq!(384, kat_set.length);
    for test in kat_set.tests {
        let hash = sha3::sha3_384(&test.msg);
        assert_eq!(test.digest, hex::encode(hash), "length {} failed", test.len);
    }
}

#[test]
fn test_large_vectors() {
    let kat_set = KatSet::load(Path::new(
        "tests/test-vectors/byte-oriented/SHA3_384LongMsg.rsp",
    ));
    assert_eq!(384, kat_set.length);
    for test in kat_set.tests {
        let hash = sha3::sha3_384(&test.msg);
        assert_eq!(test.digest, hex::encode(hash), "length {} failed", test.len);
    }
}
