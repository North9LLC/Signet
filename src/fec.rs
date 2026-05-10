// Reed-Solomon RS(20,16) over GF(256).
//
// Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D.
// 16 data bytes, 4 parity bytes (t=2, corrects up to 2 symbol errors).
// Generator polynomial roots: alpha^0, alpha^1, alpha^2, alpha^3 where alpha = 0x02.
// Systematic encoding: codeword = [data[0..16] | parity[0..4]].
//
// Convention throughout:
//   - "Low-degree-first" polynomials: p[0] = constant term, p[deg] = leading coefficient.
//     Used for generator, sigma (error locator), omega (error evaluator).
//   - The codeword is stored "high-degree-first": cw[0] = coefficient of x^(N-1), cw[N-1] = constant.
//     Evaluation of the codeword uses forward Horner (eval_codeword).
//
// Decoding uses:
//   - Berlekamp-Massey for the error-locator polynomial.
//   - Chien search to find error positions.
//   - Forney formula to compute error magnitudes.

use std::sync::OnceLock;

// GF(256) tables -----------------------------------------------------------------

struct GfTables {
    /// exp[i] = alpha^i for i in 0..255; exp[i+255] = exp[i] (doubled for wrap-free indexing).
    exp: [u8; 512],
    /// log[v] = discrete log of v (undefined for v=0).
    log: [u8; 256],
}

impl GfTables {
    fn build() -> Self {
        const POLY: u16 = 0x11D; // x^8 + x^4 + x^3 + x^2 + 1
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0u16..255 {
            exp[i as usize] = x as u8;
            exp[(i + 255) as usize] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= POLY;
            }
        }
        GfTables { exp, log }
    }
}

fn tables() -> &'static GfTables {
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(GfTables::build)
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as u16;
    let lb = t.log[b as usize] as u16;
    t.exp[((la + lb) % 255) as usize]
}

#[inline]
fn gf_div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as u16;
    let lb = t.log[b as usize] as u16;
    t.exp[((la + 255 - lb) % 255) as usize]
}

#[allow(dead_code)]
#[inline]
fn gf_pow(a: u8, n: u8) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as u16;
    t.exp[((la * (n as u16)) % 255) as usize]
}

// Polynomial evaluation ----------------------------------------------------------

/// Evaluate a low-degree-first polynomial p at x using Horner's method.
/// p[0] = constant, p[deg] = leading coefficient.
/// Result = p[0] + p[1]*x + p[2]*x^2 + ...
fn poly_eval_lo(p: &[u8], x: u8) -> u8 {
    // Horner from highest degree: accumulate from p[last] down to p[0].
    let mut acc = 0u8;
    for &c in p.iter().rev() {
        // acc = acc * x + c (but degrees are reversed in this direction)
        // p.iter().rev() gives p[last], p[last-1], ..., p[0]
        // Iteration 1 (c = p[last]): acc = p[last]
        // Iteration 2 (c = p[last-1]): acc = p[last]*x + p[last-1]
        // ...end: acc = p[last]*x^deg + ... + p[0] -- but this is high-degree-first
        // Actually for low-degree-first p = [p0, p1, ..., pn]:
        //   we want p0 + p1*x + p2*x^2 + ...
        //   = p0 + x*(p1 + x*(p2 + ... + x*pn))
        // So Horner from highest degree: start with pn, then pn*x + p(n-1), ...
        // Reversed iteration: p[n], p[n-1], ..., p[0]
        //   acc = pn, acc = pn*x + p(n-1), ..., acc = ... + p[0]
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

/// Evaluate a codeword (high-degree-first) at x using forward Horner.
/// cw[0] = coefficient of x^(N-1), cw[N-1] = constant.
/// Result = cw[0]*x^(N-1) + cw[1]*x^(N-2) + ... + cw[N-1].
fn eval_codeword(cw: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in cw.iter() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

// Generator polynomial g(x) = prod_{i=0}^{3} (x - alpha^i) --------------------
// Stored low-degree-first: g[0] = constant, g[4] = 1 (leading).

fn generator_poly() -> &'static [u8; 5] {
    static GEN: OnceLock<[u8; 5]> = OnceLock::new();
    GEN.get_or_init(|| {
        let mut g = vec![1u8]; // g(x) = 1 (constant polynomial)
        let t = tables();
        // Multiply by (x - alpha^i) for i=0..3.
        // In GF(2^m), x - alpha^i = x + alpha^i (subtraction = XOR).
        for i in 0u8..4 {
            let root = t.exp[i as usize]; // alpha^i
            let mut ng = vec![0u8; g.len() + 1];
            for (j, &c) in g.iter().enumerate() {
                ng[j + 1] ^= c;               // coefficient of x^(j+1) from c*x
                ng[j] ^= gf_mul(c, root);    // coefficient of x^j from c*root
            }
            g = ng;
        }
        let mut out = [0u8; 5];
        out.copy_from_slice(&g);
        out
    })
}

// Public API --------------------------------------------------------------------

pub const DATA_LEN: usize = 16;
pub const PARITY_LEN: usize = 4;
pub const CODE_LEN: usize = DATA_LEN + PARITY_LEN;

/// Encode 16 data bytes into a 20-byte RS(20,16) codeword.
/// Systematic: codeword = [data[0..16] | parity[0..4]].
/// cw[0] = data[0] (highest-degree coefficient), cw[19] = parity constant term.
pub fn rs_encode(data: &[u8; DATA_LEN]) -> [u8; CODE_LEN] {
    let g = generator_poly();
    // Compute remainder of x^PARITY_LEN * data(x) mod g(x) using shift-register division.
    // rem[i] holds the coefficient of x^i in the running remainder (low-degree-first).
    // The data polynomial has data[0] as the coefficient of the highest power.
    let mut rem = [0u8; PARITY_LEN];
    for &d in data.iter() {
        // New feedback = incoming data byte XOR highest-degree term of remainder.
        let feedback = d ^ rem[PARITY_LEN - 1];
        // Shift rem: rem[i] = rem[i-1] XOR feedback * g[i]
        for i in (1..PARITY_LEN).rev() {
            rem[i] = rem[i - 1] ^ gf_mul(feedback, g[i]);
        }
        rem[0] = gf_mul(feedback, g[0]);
    }
    // Assemble systematic codeword: data bytes first, then parity.
    // Parity is stored high-degree-first to match data layout:
    //   cw[DATA_LEN] = rem[PARITY_LEN-1] (coeff of x^3),
    //   cw[DATA_LEN+3] = rem[0] (constant).
    let mut cw = [0u8; CODE_LEN];
    cw[..DATA_LEN].copy_from_slice(data);
    for i in 0..PARITY_LEN {
        cw[DATA_LEN + i] = rem[PARITY_LEN - 1 - i];
    }
    cw
}

/// Attempt to decode and correct a 20-byte RS(20,16) codeword.
/// Returns the 16 data bytes if decoding succeeds (≤2 symbol errors), or None if uncorrectable.
pub fn rs_decode(codeword: &[u8; CODE_LEN]) -> Option<[u8; DATA_LEN]> {
    let t = tables();

    // Step 1: Compute syndromes S[i] = C(alpha^i) for i = 0..4.
    // The codeword polynomial has cw[0] as the highest-degree coefficient.
    let mut syndromes = [0u8; 4];
    for i in 0u8..4 {
        let root = t.exp[i as usize]; // alpha^i
        syndromes[i as usize] = eval_codeword(codeword, root);
    }

    // If all syndromes are zero, no errors.
    if syndromes.iter().all(|&s| s == 0) {
        let mut out = [0u8; DATA_LEN];
        out.copy_from_slice(&codeword[..DATA_LEN]);
        return Some(out);
    }

    // Step 2: Berlekamp-Massey to find error-locator polynomial sigma(x).
    // sigma(x) has degree ≤ t=2 and is stored low-degree-first.
    let sigma = berlekamp_massey(&syndromes)?;

    // Step 3: Chien search — find error positions.
    // Error at codeword position j corresponds to error locator alpha^(N-1-j).
    // So we find j where sigma(alpha^(-(N-1-j))) = sigma(alpha^(j-(N-1))) = 0.
    // Equivalently: sigma(X_j^{-1}) = 0 where X_j = alpha^(N-1-j).
    let num_errors = sigma.len() - 1; // degree of sigma
    let mut error_pos: Vec<usize> = Vec::with_capacity(num_errors);
    for j in 0..CODE_LEN {
        // X_j = alpha^(N-1-j); X_j^{-1} = alpha^(-(N-1-j)) = alpha^(255-(N-1-j)%255)
        let exp_val = CODE_LEN - 1 - j; // = N-1-j
        let x_j_inv_exp = (255 - exp_val % 255) % 255;
        let x_j_inv = t.exp[x_j_inv_exp];
        if poly_eval_lo(&sigma, x_j_inv) == 0 {
            error_pos.push(j);
        }
    }

    if error_pos.len() != num_errors {
        return None; // Chien found wrong count — uncorrectable
    }

    // Step 4: Forney formula for error magnitudes.
    // omega(x) = S(x) * sigma(x) mod x^(2t), stored low-degree-first.
    // S(x) = S[0] + S[1]*x + S[2]*x^2 + S[3]*x^3.
    let s_poly: Vec<u8> = syndromes.to_vec();
    let omega = poly_mul_mod(&s_poly, &sigma, 4);

    // sigma'(x) = formal derivative of sigma (in GF(2^m), coeff of x^i in sigma' is
    // sigma[i+1] * (i+1); since char=2, the term vanishes when i+1 is even).
    let sigma_prime = poly_formal_deriv(&sigma);

    let mut cw = *codeword;
    for &pos in &error_pos {
        // X_j = alpha^(N-1-pos)
        let exp_val = CODE_LEN - 1 - pos;
        let x_j = t.exp[exp_val % 255];
        let x_j_inv_exp = (255 - exp_val % 255) % 255;
        let x_j_inv = t.exp[x_j_inv_exp];

        let omega_val = poly_eval_lo(&omega, x_j_inv);
        let sigma_prime_val = poly_eval_lo(&sigma_prime, x_j_inv);

        if sigma_prime_val == 0 {
            return None; // degenerate
        }

        // Forney: e_j = X_j * omega(X_j^{-1}) / sigma'(X_j^{-1})
        // (In GF(2^m), the negation sign disappears; see Lin & Costello §6.3)
        let e_j = gf_mul(x_j, gf_div(omega_val, sigma_prime_val));
        cw[pos] ^= e_j;
    }

    // Verify: all syndromes must be zero after correction.
    for i in 0u8..4 {
        let root = t.exp[i as usize];
        if eval_codeword(&cw, root) != 0 {
            return None;
        }
    }

    let mut out = [0u8; DATA_LEN];
    out.copy_from_slice(&cw[..DATA_LEN]);
    Some(out)
}

// Berlekamp-Massey algorithm over GF(256) ---------------------------------------
// Returns sigma (error-locator polynomial, low-degree-first).
// Returns None if the number of errors exceeds t=2.

fn berlekamp_massey(syndromes: &[u8; 4]) -> Option<Vec<u8>> {
    let n = 4usize; // 2*t
    let mut c = vec![0u8; n + 1]; // error locator polynomial
    let mut b = vec![0u8; n + 1]; // previous C
    c[0] = 1;
    b[0] = 1;
    let mut l: usize = 0;
    let mut x: usize = 1; // number of iterations since last update

    for i in 0..n {
        // Discrepancy = S[i] + sum_{j=1}^{L} C[j] * S[i-j]
        let mut delta = syndromes[i];
        for j in 1..=l {
            if i >= j {
                delta ^= gf_mul(c[j], syndromes[i - j]);
            }
        }

        if delta == 0 {
            x += 1;
        } else {
            let mut t_poly = c.clone();
            for j in 0..=n {
                if j >= x && (j - x) < b.len() {
                    t_poly[j] ^= gf_mul(delta, b[j - x]);
                }
            }
            if 2 * l <= i {
                let delta_inv = gf_div(1, delta);
                b = c.iter().map(|&v| gf_mul(v, delta_inv)).collect();
                b.resize(n + 1, 0);
                l = i + 1 - l;
                x = 1;
            } else {
                x += 1;
            }
            c = t_poly;
        }
    }

    if l > 2 {
        return None;
    }

    // Trim trailing zeros.
    let mut len = c.len();
    while len > 1 && c[len - 1] == 0 {
        len -= 1;
    }
    c.truncate(len);
    Some(c)
}

// Polynomial multiplication mod x^n (low-degree-first coefficients).
fn poly_mul_mod(a: &[u8], b: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    for (i, &ai) in a.iter().enumerate() {
        if i >= n {
            break;
        }
        for (j, &bj) in b.iter().enumerate() {
            if i + j >= n {
                break;
            }
            out[i + j] ^= gf_mul(ai, bj);
        }
    }
    out
}

// Formal derivative of a low-degree-first polynomial.
// In GF(2^m), the coefficient of x^i in p'(x) is p[i+1]*(i+1);
// since char=2, this is p[i+1] when i+1 is odd, else 0.
fn poly_formal_deriv(p: &[u8]) -> Vec<u8> {
    let len = if !p.is_empty() { p.len() - 1 } else { 0 };
    let mut d = vec![0u8; len.max(1)];
    for i in 0..len {
        if (i + 1) % 2 == 1 {
            d[i] = p[i + 1];
        }
    }
    d
}

// Tests -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_basics() {
        // alpha^0 = 1, identity.
        assert_eq!(gf_mul(0x37, 1), 0x37);
        assert_eq!(gf_mul(0, 0xff), 0);
        // alpha^1 = 2: mul(2,2) = alpha^2 = 4
        assert_eq!(gf_mul(2, 2), 4);
    }

    #[test]
    fn generator_poly_roots() {
        let g = generator_poly();
        let t = tables();
        // g(alpha^i) must be 0 for i=0..3, evaluated as high-degree-first.
        for i in 0u8..4 {
            let root = t.exp[i as usize];
            // g is low-degree-first, but we can evaluate using poly_eval_lo.
            let v = poly_eval_lo(g, root);
            assert_eq!(v, 0, "generator root alpha^{} failed: poly_eval_lo={}", i, v);
        }
    }

    #[test]
    fn encode_check_syndromes() {
        // For any valid codeword C, C(alpha^i) = 0 for i=0..3.
        let data: [u8; DATA_LEN] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let cw = rs_encode(&data);
        let t = tables();
        for i in 0u8..4 {
            let root = t.exp[i as usize];
            let v = eval_codeword(&cw, root);
            assert_eq!(v, 0, "syndrome {} nonzero after encode: {}", i, v);
        }
    }

    #[test]
    fn roundtrip_clean() {
        for seed in 0u8..16 {
            let data: [u8; DATA_LEN] = std::array::from_fn(|i| (i as u8).wrapping_add(seed));
            let cw = rs_encode(&data);
            let recovered = rs_decode(&cw).expect("clean decode failed");
            assert_eq!(recovered, data, "seed {seed} roundtrip mismatch");
        }
    }

    #[test]
    fn one_error_correction() {
        let data: [u8; DATA_LEN] = [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut cw = rs_encode(&data);
        cw[5] ^= 0x42;
        let recovered = rs_decode(&cw).expect("1-error correction failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn two_error_correction() {
        let data: [u8; DATA_LEN] = [0xCA, 0xFE, 0xBA, 0xBE, 0x11, 0x22, 0x33, 0x44,
                                     0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
        let mut cw = rs_encode(&data);
        cw[0] ^= 0x01;
        cw[17] ^= 0xFF;
        let recovered = rs_decode(&cw).expect("2-error correction failed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn three_error_detection() {
        // 3 errors exceed t=2; decode should return None (or at least not silently succeed).
        let data: [u8; DATA_LEN] = [0x12; DATA_LEN];
        let mut cw = rs_encode(&data);
        cw[1] ^= 0x11;
        cw[8] ^= 0x22;
        cw[15] ^= 0x33;
        match rs_decode(&cw) {
            None => {} // expected: uncorrectable
            Some(recovered) => {
                assert_ne!(recovered, data, "3-error decode silently returned original data");
            }
        }
    }
}
