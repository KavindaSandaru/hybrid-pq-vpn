use sha2::{Digest, Sha256};

const CLIENT_HELLO: &[u8; 8] = b"NTZHELLO";
const SERVER_HELLO: &[u8; 8] = b"NTZSHLO1";
const CLIENT_AUTH: &[u8; 8] = b"NTZAUTH1";

pub fn encode_client_hello(client_id: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + client_id.len());
    packet.extend_from_slice(CLIENT_HELLO);
    packet.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    packet.extend_from_slice(client_id.as_bytes());
    packet
}

#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn decode_client_hello(data: &[u8]) -> Option<String> {
    if data.len() < 10 || &data[..8] != CLIENT_HELLO {
        return None;
    }
    let len = u16::from_be_bytes([data[8], data[9]]) as usize;
    if data.len() < 10 + len {
        return None;
    }
    std::str::from_utf8(&data[10..10 + len])
        .ok()
        .map(str::to_string)
}

#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn encode_server_hello(server_xpub: &[u8; 32], pq_public_key: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + 32 + pq_public_key.len());
    packet.extend_from_slice(SERVER_HELLO);
    packet.extend_from_slice(server_xpub);
    packet.extend_from_slice(pq_public_key);
    packet
}

pub fn decode_server_hello(data: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if data.len() < 8 + 32 || &data[..8] != SERVER_HELLO {
        return None;
    }
    let xpub: [u8; 32] = data[8..40].try_into().ok()?;
    let pq = data[40..].to_vec();
    Some((xpub, pq))
}

pub fn encode_client_auth(
    client_id: &str,
    client_xpub: &[u8; 32],
    pq_ciphertext: &[u8],
    tunnel_token: &str,
) -> Vec<u8> {
    let tag = compute_auth_tag(tunnel_token, client_xpub, pq_ciphertext);
    let mut packet = Vec::with_capacity(10 + client_id.len() + 32 + pq_ciphertext.len() + 32);
    packet.extend_from_slice(CLIENT_AUTH);
    packet.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    packet.extend_from_slice(client_id.as_bytes());
    packet.extend_from_slice(client_xpub);
    packet.extend_from_slice(pq_ciphertext);
    packet.extend_from_slice(&tag);
    packet
}

#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
pub fn decode_client_auth(data: &[u8]) -> Option<(String, [u8; 32], Vec<u8>, [u8; 32])> {
    if data.len() < 10 + 32 + 32 || &data[..8] != CLIENT_AUTH {
        return None;
    }
    let id_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    if data.len() < 10 + id_len + 32 + 32 {
        return None;
    }
    let id_start = 10;
    let xpub_start = id_start + id_len;
    let xpub_end = xpub_start + 32;
    let tag_start = data.len().checked_sub(32)?;
    if xpub_end > tag_start {
        return None;
    }
    let client_id = std::str::from_utf8(&data[id_start..xpub_start])
        .ok()?
        .to_string();
    let client_xpub: [u8; 32] = data[xpub_start..xpub_end].try_into().ok()?;
    let pq_ciphertext = data[xpub_end..tag_start].to_vec();
    let tag: [u8; 32] = data[tag_start..].try_into().ok()?;
    Some((client_id, client_xpub, pq_ciphertext, tag))
}

pub fn compute_auth_tag(
    tunnel_token: &str,
    client_xpub: &[u8; 32],
    pq_ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tunnel_token.as_bytes());
    hasher.update(client_xpub);
    hasher.update(pq_ciphertext);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_client_hello() {
        let packet = encode_client_hello("client-a");
        assert_eq!(decode_client_hello(&packet).as_deref(), Some("client-a"));
    }

    #[test]
    fn round_trips_server_hello() {
        let xpub = [7u8; 32];
        let pq = vec![9u8; 1184];
        let packet = encode_server_hello(&xpub, &pq);
        let decoded = decode_server_hello(&packet).expect("server hello should decode");
        assert_eq!(decoded.0, xpub);
        assert_eq!(decoded.1, pq);
    }

    #[test]
    fn round_trips_client_auth_and_stable_tag() {
        let xpub = [3u8; 32];
        let pq = vec![4u8; 1088];
        let packet = encode_client_auth("client-b", &xpub, &pq, "secret-token");
        let decoded = decode_client_auth(&packet).expect("auth packet should decode");
        assert_eq!(decoded.0, "client-b");
        assert_eq!(decoded.1, xpub);
        assert_eq!(decoded.2, pq);
        assert_eq!(
            decoded.3,
            compute_auth_tag("secret-token", &xpub, &decoded.2)
        );
    }
}
