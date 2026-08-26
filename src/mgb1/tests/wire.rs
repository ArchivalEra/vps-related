//! Wire-format test vectors: the contract shared by client, box and any
//! future reimplementation (the JS relay decodes the same bytes by hand).

use mgb1::*;

fn wire(seed: u8, len: usize) -> Vec<u8> {
    let mut v = vec![seed; len];
    v[0] = seed;
    v[1] = seed.wrapping_add(1);
    v
}

#[test]
fn roundtrip_three_slots() {
    let a = wire(1, 12);
    let b = wire(2, 40);
    let c = wire(3, 65535);
    let packed = encode(&[&a, &b, &c]).unwrap();
    assert!(is_mgb1(&packed));
    let slots = decode(&packed).unwrap();
    assert_eq!(slots.len(), 3);
    assert_eq!(slots[0].as_deref(), Some(a.as_slice()));
    assert_eq!(slots[1].as_deref(), Some(b.as_slice()));
    assert_eq!(slots[2].as_deref(), Some(c.as_slice()));
}

#[test]
fn max_size_slot_roundtrips() {
    let big = wire(9, MAX_WIRE);
    let packed = encode(&[&big]).unwrap();
    assert!(packed.len() <= MAX_CONTAINER);
    assert_eq!(decode(&packed).unwrap()[0].as_deref(), Some(big.as_slice()));
}

#[test]
fn rejects_oversize_count_and_tiny_slots() {
    // 65 slots cannot be encoded
    let items: Vec<Vec<u8>> = (0..65).map(|i| wire(i as u8, 12)).collect();
    let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
    assert!(matches!(encode(&refs), Err(Error::BadCount(65))));
    // an 11-byte slot is below MIN_WIRE
    let tiny = wire(1, 11);
    assert!(matches!(
        encode(&[tiny.as_slice()]),
        Err(Error::BadSlotLen(11))
    ));
}

#[test]
fn decode_salvages_prefix_on_truncation() {
    let a = wire(1, 20);
    let b = wire(2, 30);
    let mut packed = encode(&[&a, &b]).unwrap();
    packed.truncate(packed.len() - 10); // cut into slot b
    let slots = decode(&packed).unwrap();
    assert_eq!(slots.len(), 2, "count header still declares both");
    assert_eq!(slots[0].as_deref(), Some(a.as_slice()), "prefix salvaged");
    assert!(slots[1].is_none(), "cut slot degrades to None");
}

#[test]
fn empty_slots_decode_to_none() {
    // [MGB1][flags=0][count=2][len=0][len=0] — both slots failed upstream
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    let slots = decode(&buf).unwrap();
    assert!(slots.iter().all(|s| s.is_none()));
}

#[test]
fn bad_magic_is_rejected_not_guessed() {
    let not_mgb1 = vec![0xAB_u8, 0xCD, 0x01, 0x00, 0x00, 1, 0, 0]; // plain DNS query shape
    assert!(!is_mgb1(&not_mgb1));
    assert!(matches!(decode(&not_mgb1), Err(Error::BadMagic)));
}

#[test]
fn handshake_roundtrip_and_rejection() {
    let hs = encode_handshake("client-uuid-1234").unwrap();
    assert_eq!(decode_handshake(&hs).unwrap().as_deref(), Some("client-uuid-1234"));
    // a regular container is NOT a handshake
    let a = wire(5, 12);
    let packed = encode(&[a.as_slice()]).unwrap();
    assert_eq!(decode_handshake(&packed).unwrap(), None);
    // invalid utf8 in uuid block -> error, never silent garbage
    let mut bad = encode_handshake("x").unwrap();
    let n = bad.len();
    bad[n - 1] = 0xFF;
    assert!(decode_handshake(&bad).is_err());
}
