//! Basic parser and datastructures for known answer tests.

use std::{fs, path::Path};

pub struct KatSet {
    /// Digest length
    pub length: usize,
    pub tests: Vec<Test>,
}

pub struct Test {
    pub len: usize,
    pub msg: Vec<u8>,
    pub digest: String,
}

impl KatSet {
    pub fn load(path: &Path) -> Self {
        let content = fs::read_to_string(path).expect("unable to read test file");
        Self::parse(&content)
    }

    fn parse(inp: &str) -> Self {
        // TODO: This parsing code could definitely be done more elegantly and with
        // better error handling
        let mut tests = vec![];
        let mut lines = inp
            .lines()
            .filter(|line| !(line.starts_with('#') || line.is_empty()));

        let mut first_line = lines.next().expect("empty file");
        first_line = first_line.strip_prefix("[L = ").expect("No length");
        first_line = first_line.strip_suffix(']').expect("missing ']'");
        let length = first_line.parse().expect("L can't be parsed as usize");

        while let Some(len_line) = lines.next() {
            let len = len_line
                .strip_prefix("Len = ")
                .expect("missing Len")
                .parse()
                .expect("unable to parse Len");
            assert_eq!(0, len % 8);

            let mut msg = hex::decode(
                lines
                    .next()
                    .expect("missing Msg")
                    .strip_prefix("Msg = ")
                    .expect("missing msg"),
            )
            .expect("unable to decode msg");
            msg.truncate(len / 8);
            let digest = lines
                .next()
                .expect("missing MD")
                .strip_prefix("MD = ")
                .expect("missing MD")
                .to_owned();

            tests.push(Test { len, msg, digest });
        }
        KatSet { length, tests }
    }
}
