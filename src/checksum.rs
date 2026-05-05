pub fn ones_complement_sum(bytes: &[u8], checksum_offset: Option<usize>) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    
    let mut sum = chunks
        .by_ref()
        .fold(0u32, |acc, chunk| {
            acc + u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        });

    if let [odd] = chunks.remainder() {
        sum += (*odd as u32) << 8;
    }

    if let Some(offset) = checksum_offset {
         debug_assert!(
            offset.saturating_add(1) < bytes.len(),
            "checksum_offset {offset} is out of bounds for slice of len {}",
            bytes.len()
        );
        sum -= u32::from_be_bytes([0, 0, bytes[offset], bytes[offset + 1]]);
    }

    let low = (sum & 0xffff) as u16;
    let high = (sum >> 16) as u16;
    low.wrapping_add(high)  
}

// Returns true if the checksum over `bytes` is valid.
// Pass ALL header bytes including the stored checksum field.
// A correct header produces a sum of 0xffff.
pub fn verify(bytes: &[u8]) -> bool {
    ones_complement_sum(bytes, None) == 0xffff
}

pub fn compute(bytes: &[u8], checksum_offset: usize) -> u16 {
    !ones_complement_sum(bytes, Some(checksum_offset))
}