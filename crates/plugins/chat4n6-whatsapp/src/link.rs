use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedLink {
    pub url: String,
    pub scheme: String,
    pub domain: String,
    pub path: String,
}

/// Extract all URLs from a text string using regex.
/// Supports http:// and https:// URLs. Returns empty vec if none found.
pub fn extract_urls(text: &str) -> Vec<ExtractedLink> {
    todo!("implement extract_urls")
}

/// Parse a URL string into scheme, domain, path components.
pub fn parse_url_components(url: &str) -> Option<ExtractedLink> {
    todo!("implement parse_url_components")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_url() {
        let urls = extract_urls("Check out https://example.com for more info");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url, "https://example.com");
    }

    #[test]
    fn test_multiple_urls() {
        let urls = extract_urls("See https://foo.com and http://bar.org");
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn test_http_scheme() {
        let urls = extract_urls("Visit http://example.com");
        assert_eq!(urls[0].scheme, "http");
    }

    #[test]
    fn test_https_scheme() {
        let urls = extract_urls("Visit https://example.com");
        assert_eq!(urls[0].scheme, "https");
    }

    #[test]
    fn test_url_with_path_and_query() {
        let urls = extract_urls("https://example.com/path/to/page?q=hello&lang=en");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].path.contains("path/to/page"), "path: {}", urls[0].path);
    }

    #[test]
    fn test_no_url_in_text() {
        let urls = extract_urls("Just a plain message with no links");
        assert_eq!(urls.len(), 0);
    }

    #[test]
    fn test_url_at_start_of_text() {
        let urls = extract_urls("https://start.com is a great site");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].domain, "start.com");
    }

    #[test]
    fn test_url_at_end_of_text() {
        let urls = extract_urls("Visit our site at https://end.com");
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn test_domain_extraction() {
        let link = parse_url_components("https://www.example.org/page").unwrap();
        assert_eq!(link.domain, "www.example.org");
    }

    #[test]
    fn test_path_extraction() {
        let link = parse_url_components("https://example.com/a/b/c").unwrap();
        assert_eq!(link.path, "/a/b/c");
    }

    #[test]
    fn test_empty_text() {
        let urls = extract_urls("");
        assert_eq!(urls.len(), 0);
    }

    #[test]
    fn test_email_not_matched() {
        // Emails are not URLs — should not be extracted
        let urls = extract_urls("Contact us at admin@example.com for help");
        assert_eq!(urls.len(), 0);
    }

    #[test]
    fn test_parse_url_invalid_returns_none() {
        assert!(parse_url_components("not a url").is_none());
    }
}
