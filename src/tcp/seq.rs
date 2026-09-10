pub fn wrapping_after(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

pub fn wrapping_before(a: u32, b: u32) -> bool {
    wrapping_after(b, a)
}

pub fn wrapping_after_or_eq(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

pub fn wrapping_before_or_eq(a: u32, b: u32) -> bool {
    wrapping_after_or_eq(b, a)
}

pub fn wrapping_distance(start: u32, end: u32) -> u32 {
    end.wrapping_sub(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_normal_case() {
        assert!(wrapping_after(100, 50));
        assert!(!wrapping_after(50, 100));
        assert!(!wrapping_after(50, 50));
    }

    #[test]
    fn after_wraparound() {
        // 500 is "after" 4294967200 because we wrapped around
        assert!(wrapping_after(500, 4_294_967_200));
        assert!(!wrapping_after(4_294_967_200, 500));
    }

    #[test]
    fn after_exact_half_is_ambiguous_returns_false() {
        // exactly 2^31 apart — not considered "after" by convention
        assert!(!wrapping_after(0x8000_0000, 0));
        assert!(!wrapping_after(0, 0x8000_0000));
    }

    #[test]
    fn before_is_inverse_of_after() {
        assert!(wrapping_before(50, 100));
        assert!(!wrapping_before(100, 50));
    }

    #[test]
    fn after_or_eq_includes_equal() {
        assert!(wrapping_after_or_eq(100, 100));
        assert!(wrapping_after_or_eq(101, 100));
        assert!(!wrapping_after_or_eq(99, 100));
    }

    #[test]
    fn distance_normal() {
        assert_eq!(wrapping_distance(100, 200), 100);
    }

    #[test]
    fn distance_wraparound() {
        assert_eq!(wrapping_distance(4_294_967_200, 500), 596);
    }

    #[test]
    fn distance_zero_when_equal() {
        assert_eq!(wrapping_distance(42, 42), 0);
    }
}
