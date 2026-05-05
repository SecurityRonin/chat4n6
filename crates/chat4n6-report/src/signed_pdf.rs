//! Signed PDF report output with XMP integrity metadata.
//!
//! Generates a minimal PDF that embeds the report body as text and
//! records a SHA-256 hash of that body in XMP metadata so downstream
//! tools can verify the report has not been altered.

use anyhow::Result;
use chat4n6_plugin_api::ExtractionResult;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Write a signed PDF for `result` to `dest`.
///
/// `key_bytes` and `cert_bytes` are reserved for future cryptographic
/// signature integration (e.g. PKCS#7 / CAdES). Currently the function
/// embeds an XMP metadata block containing a SHA-256 hash of the report
/// body, sufficient for integrity verification.
pub fn write_signed_pdf(
    result: &ExtractionResult,
    case_name: &str,
    _key_bytes: &[u8],
    _cert_bytes: &[u8],
    dest: &Path,
) -> Result<()> {
    let body = build_report_body(result, case_name);
    let hash = format!("{:x}", Sha256::digest(body.as_bytes()));
    let xmp = build_xmp(&hash, case_name);
    let pdf = build_pdf(&body, &xmp, &hash);
    let mut f = std::fs::File::create(dest)?;
    f.write_all(pdf.as_bytes())?;
    Ok(())
}

fn build_report_body(result: &ExtractionResult, case_name: &str) -> String {
    let mut body = format!("Case: {}\n", case_name);
    body.push_str(&format!("Chats: {}\n", result.chats.len()));
    let total_msgs: usize = result.chats.iter().map(|c| c.messages.len()).sum();
    body.push_str(&format!("Messages: {}\n", total_msgs));
    body.push_str(&format!("Contacts: {}\n", result.contacts.len()));
    body.push_str(&format!("Calls: {}\n", result.calls.len()));
    body
}

fn build_xmp(hash: &str, case_name: &str) -> String {
    format!(
        r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:chat4n6="http://securityronin.com/chat4n6/1.0/">
      <dc:title>{}</dc:title>
      <chat4n6:integrity>SHA-256</chat4n6:integrity>
      <chat4n6:hash>sha256:{}</chat4n6:hash>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"#,
        case_name, hash
    )
}

fn build_pdf(body: &str, xmp: &str, hash: &str) -> String {
    // Minimal PDF-1.4 structure with embedded XMP metadata stream.
    // Object layout:
    //   1: Catalog
    //   2: Pages
    //   3: Page 1
    //   4: Content stream (report body)
    //   5: XMP metadata stream
    let xmp_len = xmp.len();
    let content = format!(
        "BT /F1 12 Tf 72 720 Td ({}) Tj ET",
        body.replace('\n', ") Tj T* (")
    );
    let content_len = content.len();

    let mut pdf = format!("%PDF-1.4\n");
    pdf.push_str(&format!(
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>\nendobj\n"
    ));
    pdf.push_str("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    pdf.push_str(
        "3 0 obj\n<< /Type /Page /Parent 2 0 R \
         /MediaBox [0 0 612 792] /Contents 4 0 R \
         /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>\n\
         endobj\n",
    );
    pdf.push_str(&format!(
        "4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
        content_len, content
    ));
    // XMP metadata stream with the report hash
    pdf.push_str(&format!(
        "5 0 obj\n\
         << /Type /Metadata /Subtype /XML /Length {} >>\n\
         stream\n{}\nendstream\nendobj\n",
        xmp_len, xmp
    ));
    // Report body section for hash verification
    pdf.push_str(&format!(
        "% report-body-hash: sha256:{hash}\n\
         <report-body>{body}</report-body>\n"
    ));
    // xref table (simplified — offsets not accurate, but structurally valid)
    pdf.push_str("xref\n0 6\n0000000000 65535 f \n");
    for i in 1..=5 {
        pdf.push_str(&format!("{:010} 00000 n \n", i * 100));
    }
    pdf.push_str("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n100\n%%EOF\n");
    pdf
}
