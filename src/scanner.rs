#[derive(Debug, Clone)]
pub struct Signature {
    #[allow(dead_code)]
    pub pattern: String,
    bytes: Vec<Option<u8>>,
}

impl Signature {
    pub fn parse(pattern: &str) -> anyhow::Result<Self> {
        let bytes: Vec<Option<u8>> = pattern
            .split_whitespace()
            .map(|tok| {
                if tok == "?" || tok == "??" {
                    Ok(None)
                } else {
                    u8::from_str_radix(tok, 16)
                        .map(Some)
                        .map_err(|e| anyhow::anyhow!("invalid hex byte '{tok}': {e}"))
                }
            })
            .collect::<anyhow::Result<_>>()?;

        if bytes.is_empty() {
            anyhow::bail!("signature pattern must not be empty");
        }

        Ok(Self {
            pattern: pattern.to_string(),
            bytes,
        })
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn scan(&self, haystack: &[u8]) -> Vec<usize> {
        let pat = &self.bytes;
        let pat_len = pat.len();

        if pat_len == 0 || haystack.len() < pat_len {
            return Vec::new();
        }

        let first = pat[0];
        let max_start = haystack.len() - pat_len;

        haystack[..=max_start]
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| {
                match first {
                    Some(fb) if b != fb => return None,
                    _ => {}
                }
                if self.matches_at(haystack, i) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        self.bytes
            .iter()
            .enumerate()
            .all(|(j, &pat_byte)| match pat_byte {
                Some(required) => haystack[offset + j] == required,
                None => true,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exact() {
        let sig = Signature::parse("48 8d 71 50").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(
            sig.bytes,
            vec![Some(0x48), Some(0x8d), Some(0x71), Some(0x50),]
        );
    }

    #[test]
    fn test_parse_wildcard() {
        let sig = Signature::parse("48 ?? 71 ??").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig.bytes[0], Some(0x48));
        assert_eq!(sig.bytes[1], None);
        assert_eq!(sig.bytes[2], Some(0x71));
        assert_eq!(sig.bytes[3], None);
    }

    #[test]
    fn test_parse_single_question() {
        let sig = Signature::parse("48 ? 71 ??").unwrap();
        assert_eq!(sig.len(), 4);
        assert_eq!(sig.bytes[1], None);
        assert_eq!(sig.bytes[3], None);
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!(Signature::parse("ZZ 8d").is_err());
    }

    #[test]
    fn test_parse_empty() {
        assert!(Signature::parse("").is_err());
        assert!(Signature::parse("   ").is_err());
    }

    #[test]
    fn test_scan_exact_match() {
        let sig = Signature::parse("48 8d 71 50").unwrap();
        let haystack = b"\x00\x00\x48\x8d\x71\x50\xff\xff";
        let matches = sig.scan(haystack);
        assert_eq!(matches, vec![2]);
    }

    #[test]
    fn test_scan_wildcard_match() {
        let sig = Signature::parse("48 ?? 71 ??").unwrap();
        let haystack = b"\x48\x99\x71\xAA\x00";
        let matches = sig.scan(haystack);
        assert_eq!(matches, vec![0]);
    }

    #[test]
    fn test_scan_no_match() {
        let sig = Signature::parse("48 8d 71 50").unwrap();
        let haystack = b"\x48\x8d\x71\x51\x00";
        let matches = sig.scan(haystack);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_multiple_matches() {
        let sig = Signature::parse("90 90").unwrap();
        let haystack = b"\x90\x90\xcc\x90\x90";
        let matches = sig.scan(haystack);
        assert_eq!(matches, vec![0, 3]);
    }

    #[test]
    fn test_scan_too_short() {
        let sig = Signature::parse("48 8d 71 50 55 66").unwrap();
        let haystack = b"\x48\x8d";
        let matches = sig.scan(haystack);
        assert!(matches.is_empty());
    }
}
