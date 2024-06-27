module tucana_std::math_u256 {
    use std::string::{Self, String};
    use std::vector;

    const MAX_U256: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    public fun div_mod(num: u256, denom: u256): (u256, u256) {
        let p = num / denom;
        let r: u256 = num - (p * denom);
        (p, r)
    }

    public fun shlw(n: u256): u256 {
        n << 64
    }

    public fun shrw(n: u256): u256 {
        n >> 64
    }

    public fun checked_shlw(n: u256): (u256, bool) {
        let mask = 0xffffffffffffffff << 192;
        if (n > mask) {
            (0, true)
        } else {
            ((n << 64), false)
        }
    }

    public fun div_round(num: u256, denom: u256, round_up: bool): u256 {
        let p = num / denom;
        if (round_up && ((p * denom) != num)) {
            p + 1
        } else {
            p
        }
    }

    public fun add_check(num1: u256, num2: u256): bool {
        (MAX_U256 - num1 >= num2)
    }

    public fun stringify(num: u256): String {
        if (num == 0) {
            return string::utf8(b"0")
        };
        let remainder: u8;
        let digits = vector::empty<u8>();
        while (num > 0) {
            remainder = (num % 10 as u8);
            num = num / 10;
            vector::push_back(&mut digits, remainder + 48);
        };
        vector::reverse(&mut digits);
        string::utf8(digits)
    }

    #[test]
    fun test_div_round() {
        div_round(1, 1, true);
    }

    #[test]
    fun test_add() {
        1000u256 + 1000u256;
    }
}
