//! Password and passphrase generation (OsRng, unbiased sampling).

use rand_core::{OsRng, RngCore};
use serde::Deserialize;

use crate::{Error, Result};

const WORDS: &str = include_str!("eff_large_wordlist.txt");

#[derive(Clone, Debug, Deserialize)]
pub struct GeneratorOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Skip look-alike characters: I l 1 O 0 o.
    pub exclude_similar: bool,
}

const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const SIMILAR: &str = "Il1O0o";

/// Unbiased index in `0..n` (rejection sampling).
fn below(n: usize) -> usize {
    let n = n as u32;
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let x = OsRng.next_u32();
        if x < zone {
            return (x % n) as usize;
        }
    }
}

pub fn generate_password(o: &GeneratorOptions) -> Result<String> {
    if !(4..=128).contains(&o.length) {
        return Err(Error::Invalid("password length must be 4..=128"));
    }
    let classes: Vec<Vec<char>> = [
        (o.upper, ('A'..='Z').collect::<String>()),
        (o.lower, ('a'..='z').collect::<String>()),
        (o.digits, ('0'..='9').collect::<String>()),
        (o.symbols, SYMBOLS.to_string()),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| set.chars().filter(|c| !(o.exclude_similar && SIMILAR.contains(*c))).collect())
    .collect();
    if classes.is_empty() {
        return Err(Error::Invalid("select at least one character class"));
    }
    let all: Vec<char> = classes.concat();
    // One char from each class guarantees coverage; the rest from the union; then shuffle.
    let mut out: Vec<char> = classes.iter().map(|set| set[below(set.len())]).collect();
    out.extend((out.len()..o.length).map(|_| all[below(all.len())]));
    for i in (1..out.len()).rev() {
        out.swap(i, below(i + 1));
    }
    Ok(out.into_iter().collect())
}

pub fn generate_passphrase(words: usize, separator: &str) -> Result<String> {
    if !(3..=20).contains(&words) {
        return Err(Error::Invalid("passphrase must have 3..=20 words"));
    }
    let list: Vec<&str> = WORDS.lines().collect();
    Ok((0..words).map(|_| list[below(list.len())]).collect::<Vec<_>>().join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn opts(length: usize) -> GeneratorOptions {
        GeneratorOptions { length, upper: true, lower: true, digits: true, symbols: true, exclude_similar: false }
    }

    #[test]
    fn password_has_length_and_every_selected_class() {
        for _ in 0..200 {
            let p = generate_password(&opts(4)).unwrap();
            assert_eq!(p.chars().count(), 4);
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| c.is_ascii_punctuation()));
        }
    }

    #[test]
    fn only_selected_classes_and_no_lookalikes() {
        let o = GeneratorOptions { symbols: false, upper: false, exclude_similar: true, ..opts(64) };
        for _ in 0..50 {
            let p = generate_password(&o).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert!(!p.chars().any(|c| "Il1O0o".contains(c)));
        }
    }

    #[test]
    fn rejects_bad_options() {
        let none = GeneratorOptions { upper: false, lower: false, digits: false, symbols: false, ..opts(16) };
        assert!(matches!(generate_password(&none), Err(Error::Invalid(_))));
        assert!(matches!(generate_password(&opts(3)), Err(Error::Invalid(_))));
        assert!(matches!(generate_password(&opts(129)), Err(Error::Invalid(_))));
        assert!(matches!(generate_passphrase(2, "-"), Err(Error::Invalid(_))));
    }

    #[test]
    fn passphrase_uses_wordlist() {
        let p = generate_passphrase(6, "-").unwrap();
        let words: Vec<&str> = p.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|w| WORDS.lines().any(|l| l == *w)));
        assert_ne!(p, generate_passphrase(6, "-").unwrap());
    }
}
