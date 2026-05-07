/// TLObject constructor IDs found in Telegram Android messages_v2.data BLOB.
const CID_MESSAGE: u32 = 0x94dd1f3f;
const CID_MESSAGE_SERVICE: u32 = 0xa7ab1991;
const CID_MESSAGE_EMPTY: u32 = 0x1c9b1027;

/// Decode the message text from a TLObject-serialized `data` BLOB in messages_v2.
///
/// Layout of TL_message:
///   [0..4]  constructor ID (LE u32) = 0x94dd1f3f
///   [4..8]  flags (LE u32)
///   [8]     TL string length byte N  (if N < 254, the string occupies bytes 9..9+N)
///           if N == 254, next 3 bytes (LE) give the true length (3-byte prefix form)
///
/// Returns `None` for service/empty messages, malformed data, or non-UTF-8.
pub fn decode_tl_message_text(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }

    let cid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match cid {
        CID_MESSAGE_SERVICE | CID_MESSAGE_EMPTY => return None,
        CID_MESSAGE => {}
        _ => return None,
    }

    // Text starts at offset 8 as a TL-encoded string.
    let len_byte = *data.get(8)? as usize;

    let (text_start, text_len) = if len_byte < 254 {
        // Simple form: length is len_byte, text begins at offset 9.
        (9usize, len_byte)
    } else if len_byte == 254 {
        // 3-byte little-endian length prefix.
        if data.len() < 12 {
            return None;
        }
        let n = u32::from_le_bytes([data[9], data[10], data[11], 0]) as usize;
        (12usize, n)
    } else {
        // 255 is reserved / not used in this context.
        return None;
    };

    let end = text_start.checked_add(text_len)?;
    let bytes = data.get(text_start..end)?;
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice_is_none() {
        assert_eq!(decode_tl_message_text(&[]), None);
    }

    #[test]
    fn too_short_is_none() {
        assert_eq!(decode_tl_message_text(&[0x3f, 0x1f, 0xdd, 0x94, 0, 0]), None);
    }
}
