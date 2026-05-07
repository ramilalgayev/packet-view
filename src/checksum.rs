#[inline]
fn sum_words(bytes: &[u8]) -> u32 {
    let (words, rem) = bytes.as_chunks::<2>();

    let mut sum = words.iter().fold(0u32, |acc, word| {
        acc + u16::from_be_bytes(*word) as u32
    });

    if let [last] = rem {
        sum += (*last as u32) << 8;
    }

    sum
}

pub fn ones_complement_sum(
    bytes: &[u8],
    checksum_offset: Option<usize>,
) -> u16 {
    debug_assert!(
        checksum_offset
            .map(|offset| offset + 1 < bytes.len() && offset % 2 == 0)
            .unwrap_or(true)
    );

    let sum = match checksum_offset {
        Some(offset) => {
            sum_words(&bytes[..offset])
                + sum_words(&bytes[offset + 2..])
        }
        None => sum_words(bytes),
    };

    fold(sum)
}

#[inline]
fn fold(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum as u16
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

pub fn transport_checksum_with_pseudo_header(
    pseudo_header: &[u8],
    segment: &[u8],
    checksum_offset: usize,
) -> u16 {
    let pseudo_sum = ones_complement_sum(pseudo_header, None) as u32;
    let segment_sum = ones_complement_sum(segment, Some(checksum_offset)) as u32;

    !fold(pseudo_sum + segment_sum)
}