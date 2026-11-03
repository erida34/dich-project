//! Sensitive credential and secret redaction for URLs, tokens, and private keys.

/// Redact credentials in URLs, bearer/auth tokens, and private key blocks.
pub fn redact_sensitive(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;

    while !remaining.is_empty() {
        if let Some(pos) = remaining.find("://") {
            let scheme_start = remaining[..pos]
                .rfind(|c: char| !c.is_alphanumeric() && c != '+' && c != '-' && c != '.')
                .map(|p| p + 1)
                .unwrap_or(0);
            result.push_str(&remaining[..scheme_start]);
            let url_part = &remaining[scheme_start..];

            let url_end = url_part
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '>' | '<' | '`'))
                .unwrap_or(url_part.len());
            let url_str = &url_part[..url_end];
            result.push_str(&redact_url_userinfo(url_str));
            remaining = &url_part[url_end..];
        } else {
            result.push_str(remaining);
            break;
        }
    }

    let redacted = redact_bearer_tokens(&result);
    redact_private_keys(&redacted)
}

fn redact_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if let Some(at_idx) = authority.rfind('@') {
        let userinfo = &authority[..at_idx];
        let host_port = &authority[at_idx + 1..];
        let redacted_userinfo = if userinfo.contains(':') {
            "***:***"
        } else {
            "***"
        };
        format!(
            "{}://{}@{}{}",
            &url[..scheme_end],
            redacted_userinfo,
            host_port,
            &rest[authority_end..]
        )
    } else {
        url.to_string()
    }
}

fn redact_bearer_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rem = input;
    while let Some(idx) = rem.find("Bearer ") {
        out.push_str(&rem[..idx]);
        out.push_str("Bearer [REDACTED]");
        let after = &rem[idx + 7..];
        let token_len = after
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';'))
            .unwrap_or(after.len());
        rem = &after[token_len..];
    }
    out.push_str(rem);
    out
}

fn redact_private_keys(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rem = input;
    while let Some(start) = rem.find("-----BEGIN") {
        let after = &rem[start..];
        if let Some(end_header) = after.find("KEY-----") {
            let header_line_end = end_header + 8;
            if let Some(end_footer) = after[header_line_end..].find("-----END") {
                let footer_start = header_line_end + end_footer;
                let footer_after = &after[footer_start..];
                if let Some(final_end) = footer_after.find("KEY-----") {
                    let total_end = start + footer_start + final_end + 8;
                    out.push_str(&rem[..start]);
                    out.push_str("[REDACTED PRIVATE KEY]");
                    rem = &rem[total_end..];
                    continue;
                }
            }
        }
        out.push_str(&rem[..start + 10]);
        rem = &rem[start + 10..];
    }
    out.push_str(rem);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_url_credentials() {
        assert_eq!(
            redact_sensitive("Fetching from https://user:secret123@archive.debian.org/debian"),
            "Fetching from https://***:***@archive.debian.org/debian"
        );
        assert_eq!(
            redact_sensitive("Proxy at http://token_only@proxy.corp:8080/"),
            "Proxy at http://***@proxy.corp:8080/"
        );
        assert_eq!(
            redact_sensitive("Standard URL https://deb.debian.org/debian is untouched"),
            "Standard URL https://deb.debian.org/debian is untouched"
        );
    }

    #[test]
    fn redacts_bearer_tokens() {
        assert_eq!(
            redact_sensitive("Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz in request"),
            "Header: Bearer [REDACTED] in request"
        );
    }

    #[test]
    fn redacts_private_key_blocks() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            redact_sensitive(&format!("Key data:\n{key}\nend of message")),
            "Key data:\n[REDACTED PRIVATE KEY]\nend of message"
        );
    }
}
