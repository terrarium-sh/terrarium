#[must_use]
pub fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    ((1..=253).contains(&hostname.len())
        && hostname.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }))
    .then_some(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_hostname_labels() {
        assert_eq!(
            normalize_hostname("WWW.Example.COM."),
            Some("www.example.com".into())
        );
        for name in ["", "a..example", "-a.example", "a-.example", "a_b.example"] {
            assert_eq!(normalize_hostname(name), None, "{name}");
        }
    }
}
