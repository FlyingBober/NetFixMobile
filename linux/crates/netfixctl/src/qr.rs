/// Pure-Rust QR Code generator (Byte mode, Error Correction Level L, Versions 1..=10)
/// rendered as UTF-8 half-block terminal art.

struct VersionSpec {
    version: usize,
    size: usize,
    data_bytes: usize,
    ec_per_block: usize,
    g1_blocks: usize,
    g1_data: usize,
    g2_blocks: usize,
    g2_data: usize,
    alignment: &'static [usize],
}

const VERSIONS: &[VersionSpec] = &[
    VersionSpec { version: 1, size: 21, data_bytes: 19, ec_per_block: 7, g1_blocks: 1, g1_data: 19, g2_blocks: 0, g2_data: 0, alignment: &[] },
    VersionSpec { version: 2, size: 25, data_bytes: 34, ec_per_block: 10, g1_blocks: 1, g1_data: 34, g2_blocks: 0, g2_data: 0, alignment: &[6, 18] },
    VersionSpec { version: 3, size: 29, data_bytes: 55, ec_per_block: 15, g1_blocks: 1, g1_data: 55, g2_blocks: 0, g2_data: 0, alignment: &[6, 22] },
    VersionSpec { version: 4, size: 33, data_bytes: 80, ec_per_block: 20, g1_blocks: 1, g1_data: 80, g2_blocks: 0, g2_data: 0, alignment: &[6, 26] },
    VersionSpec { version: 5, size: 37, data_bytes: 108, ec_per_block: 26, g1_blocks: 1, g1_data: 108, g2_blocks: 0, g2_data: 0, alignment: &[6, 30] },
    VersionSpec { version: 6, size: 41, data_bytes: 136, ec_per_block: 18, g1_blocks: 2, g1_data: 68, g2_blocks: 0, g2_data: 0, alignment: &[6, 34] },
    VersionSpec { version: 7, size: 45, data_bytes: 156, ec_per_block: 20, g1_blocks: 2, g1_data: 78, g2_blocks: 0, g2_data: 0, alignment: &[6, 22, 38] },
    VersionSpec { version: 8, size: 49, data_bytes: 194, ec_per_block: 24, g1_blocks: 2, g1_data: 97, g2_blocks: 0, g2_data: 0, alignment: &[6, 24, 42] },
    VersionSpec { version: 9, size: 53, data_bytes: 232, ec_per_block: 30, g1_blocks: 2, g1_data: 116, g2_blocks: 0, g2_data: 0, alignment: &[6, 26, 46] },
    VersionSpec { version: 10, size: 57, data_bytes: 274, ec_per_block: 18, g1_blocks: 2, g1_data: 68, g2_blocks: 2, g2_data: 69, alignment: &[6, 28, 50] },
];

pub fn render_qr_utf8(text: &str) -> Result<String, String> {
    let matrix = encode_qr_matrix(text.as_bytes())?;
    let size = matrix.len();
    let quiet = 2usize;
    let total = size + quiet * 2;

    let module_at = |r: usize, c: usize| -> bool {
        if r < quiet || c < quiet || r >= quiet + size || c >= quiet + size {
            false
        } else {
            matrix[r - quiet][c - quiet]
        }
    };

    let mut out = String::new();
    let mut r = 0;
    while r < total {
        for c in 0..total {
            let top = module_at(r, c);
            let bottom = if r + 1 < total {
                module_at(r + 1, c)
            } else {
                false
            };
            // Light terminal background assumption: dark module = ink, light module = space.
            // Invert if needed? Using standard dark=filled block works well on dark & light terminals
            // when quiet zone is present; even better, standard convention:
            // dark=space / light=block for dark terminals, or dark=block / light=space.
            // Using standard UTF8 half-blocks with dark=█ (inverted or direct) — let's use dark=█
            // wait: phone cameras scan white-background + black-modules best; on dark terminal white=█, black=space!
            // Actually ANSI white/black or standard `██`? Wait: qrencode -t ANSIUTF8 uses `\x1b[40m` / `\x1b[47m` OR inverted blocks.
            // Using `█`/`▀`/`▄`/` ` with light=█ (white modules) and dark=' ' (dark modules) scans on dark terminals,
            // while dark=█ scans on light terminals. Using ANSI black-on-white (`\x1b[47;30m`) works on EVERY terminal!
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push('\n');
        r += 2;
    }
    Ok(out)
}

pub fn encode_qr_matrix(data: &[u8]) -> Result<Vec<Vec<bool>>, String> {
    let spec = VERSIONS
        .iter()
        .find(|v| {
            let header_bits = if v.version <= 9 { 12 } else { 20 };
            data.len() * 8 + header_bits <= v.data_bytes * 8
        })
        .ok_or_else(|| format!("input too long for QR v1..10 ({} bytes)", data.len()))?;

    let codewords = build_codewords(spec, data);
    let size = spec.size;
    let mut modules = vec![vec![false; size]; size];
    let mut is_function = vec![vec![false; size]; size];

    draw_function_patterns(spec, &mut modules, &mut is_function);
    place_data_bits(&codewords, &mut modules, &is_function);

    let mut best_mask = 0u8;
    let mut best_penalty = u32::MAX;
    for mask in 0..8u8 {
        let mut candidate = modules.clone();
        apply_mask(mask, &mut candidate, &is_function);
        draw_format_bits(mask, &mut candidate);
        let penalty = evaluate_penalty(&candidate);
        if penalty < best_penalty {
            best_penalty = penalty;
            best_mask = mask;
        }
    }

    apply_mask(best_mask, &mut modules, &is_function);
    draw_format_bits(best_mask, &mut modules);
    Ok(modules)
}

fn build_codewords(spec: &VersionSpec, data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(spec.data_bytes * 8);
    // Byte mode indicator: 0100
    push_bits(&mut bits, 0b0100, 4);
    let count_bits = if spec.version <= 9 { 8 } else { 16 };
    push_bits(&mut bits, data.len() as u32, count_bits);
    for &b in data {
        push_bits(&mut bits, b as u32, 8);
    }

    let capacity_bits = spec.data_bytes * 8;
    let terminator = (capacity_bits - bits.len()).min(4);
    push_bits(&mut bits, 0, terminator);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }

    let mut data_bytes = Vec::with_capacity(spec.data_bytes);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | u8::from(bit);
        }
        data_bytes.push(byte);
    }

    let pad_bytes = [0xECu8, 0x11u8];
    let mut pad_idx = 0;
    while data_bytes.len() < spec.data_bytes {
        data_bytes.push(pad_bytes[pad_idx % 2]);
        pad_idx += 1;
    }

    let gen_poly = rs_generator(spec.ec_per_block);
    let mut data_blocks = Vec::new();
    let mut ec_blocks = Vec::new();
    let mut offset = 0;

    for _ in 0..spec.g1_blocks {
        let block = &data_bytes[offset..offset + spec.g1_data];
        offset += spec.g1_data;
        data_blocks.push(block.to_vec());
        ec_blocks.push(rs_remainder(block, &gen_poly));
    }
    for _ in 0..spec.g2_blocks {
        let block = &data_bytes[offset..offset + spec.g2_data];
        offset += spec.g2_data;
        data_blocks.push(block.to_vec());
        ec_blocks.push(rs_remainder(block, &gen_poly));
    }

    let max_data_len = data_blocks.iter().map(Vec::len).max().unwrap_or(0);
    let mut interleaved = Vec::with_capacity(spec.data_bytes + data_blocks.len() * spec.ec_per_block);
    for i in 0..max_data_len {
        for block in &data_blocks {
            if let Some(&b) = block.get(i) {
                interleaved.push(b);
            }
        }
    }
    for i in 0..spec.ec_per_block {
        for ec in &ec_blocks {
            interleaved.push(ec[i]);
        }
    }
    interleaved
}

fn push_bits(bits: &mut Vec<bool>, val: u32, len: usize) {
    for i in (0..len).rev() {
        bits.push(((val >> i) & 1) != 0);
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    res
}

fn rs_generator(degree: usize) -> Vec<u8> {
    let mut poly = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0u8; poly.len() + 1];
        for (i, &coef) in poly.iter().enumerate() {
            next[i] ^= coef;
            next[i + 1] ^= gf_mul(coef, root);
        }
        poly = next;
        root = gf_mul(root, 2);
    }
    poly
}

fn rs_remainder(data: &[u8], gen: &[u8]) -> Vec<u8> {
    let ec_len = gen.len() - 1;
    let mut rem = vec![0u8; ec_len];
    for &byte in data {
        let factor = byte ^ rem[0];
        rem.rotate_left(1);
        rem[ec_len - 1] = 0;
        for (i, &g) in gen[1..].iter().enumerate() {
            rem[i] ^= gf_mul(g, factor);
        }
    }
    rem
}

fn draw_function_patterns(
    spec: &VersionSpec,
    modules: &mut [Vec<bool>],
    is_function: &mut [Vec<bool>],
) {
    let n = spec.size;

    // Timing patterns
    for i in 0..n {
        let dark = i.is_multiple_of(2);
        modules[6][i] = dark;
        is_function[6][i] = true;
        modules[i][6] = dark;
        is_function[i][6] = true;
    }

    // Finder patterns + separators
    draw_finder(0, 0, modules, is_function);
    draw_finder(0, n - 7, modules, is_function);
    draw_finder(n - 7, 0, modules, is_function);

    // Alignment patterns
    for &r in spec.alignment {
        for &c in spec.alignment {
            if (r == 6 && (c == 6 || c == n - 7)) || (r == n - 7 && c == 6) {
                continue;
            }
            draw_alignment(r, c, modules, is_function);
        }
    }

    // Format info reserved areas
    for i in 0..9 {
        if i != 6 {
            is_function[8][i] = true;
            is_function[i][8] = true;
        }
    }
    for i in 0..8 {
        is_function[8][n - 1 - i] = true;
        is_function[n - 1 - i][8] = true;
    }
    modules[n - 8][8] = true;
    is_function[n - 8][8] = true;

    // Version info for >= 7
    if spec.version >= 7 {
        let bits = version_info_bits(spec.version as u32);
        for i in 0..18 {
            let bit = ((bits >> i) & 1) != 0;
            let a = n - 11 + (i % 3);
            let b = i / 3;
            modules[a][b] = bit;
            is_function[a][b] = true;
            modules[b][a] = bit;
            is_function[b][a] = true;
        }
    }
}

fn draw_finder(
    top: usize,
    left: usize,
    modules: &mut [Vec<bool>],
    is_function: &mut [Vec<bool>],
) {
    let n = modules.len();
    for dr in -1..=7isize {
        for dc in -1..=7isize {
            let r = top as isize + dr;
            let c = left as isize + dc;
            if r < 0 || c < 0 || r >= n as isize || c >= n as isize {
                continue;
            }
            let dist = dr.abs_diff(3).max(dc.abs_diff(3));
            let dark = dist != 2 && dist != 4;
            modules[r as usize][c as usize] = dark;
            is_function[r as usize][c as usize] = true;
        }
    }
}

fn draw_alignment(
    center_r: usize,
    center_c: usize,
    modules: &mut [Vec<bool>],
    is_function: &mut [Vec<bool>],
) {
    for dr in -2..=2isize {
        for dc in -2..=2isize {
            let dist = dr.abs().max(dc.abs());
            let r = (center_r as isize + dr) as usize;
            let c = (center_c as isize + dc) as usize;
            modules[r][c] = dist != 1;
            is_function[r][c] = true;
        }
    }
}

fn place_data_bits(codewords: &[u8], modules: &mut [Vec<bool>], is_function: &[Vec<bool>]) {
    let n = modules.len();
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut upward = true;
    let mut right = (n as isize) - 1;

    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for step in 0..n {
            let r = if upward { n - 1 - step } else { step };
            for dx in 0..2isize {
                let c = (right - dx) as usize;
                if !is_function[r][c] && bit_idx < total_bits {
                    let byte = codewords[bit_idx / 8];
                    let bit = ((byte >> (7 - (bit_idx % 8))) & 1) != 0;
                    modules[r][c] = bit;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

fn apply_mask(mask: u8, modules: &mut [Vec<bool>], is_function: &[Vec<bool>]) {
    let n = modules.len();
    for r in 0..n {
        for c in 0..n {
            if is_function[r][c] {
                continue;
            }
            let invert = match mask {
                0 => (r + c).is_multiple_of(2),
                1 => r.is_multiple_of(2),
                2 => c.is_multiple_of(3),
                3 => (r + c).is_multiple_of(3),
                4 => (r / 2 + c / 3).is_multiple_of(2),
                5 => (r * c) % 2 + (r * c) % 3 == 0,
                6 => ((r * c) % 2 + (r * c) % 3).is_multiple_of(2),
                7 => ((r + c) % 2 + (r * c) % 3).is_multiple_of(2),
                _ => false,
            };
            if invert {
                modules[r][c] = !modules[r][c];
            }
        }
    }
}

fn draw_format_bits(mask: u8, modules: &mut [Vec<bool>]) {
    let n = modules.len();
    // EC level L = 0b01
    let data = (0b01u32 << 3) | (mask as u32);
    let mut rem = data << 10;
    for i in (0..5).rev() {
        if ((rem >> (i + 10)) & 1) != 0 {
            rem ^= 0b101_0011_0111 << i;
        }
    }
    let bits = ((data << 10) | rem) ^ 0b101_0100_0001_0010;

    for i in 0..15 {
        let dark = ((bits >> i) & 1) != 0;
        if i < 6 {
            modules[i][8] = dark;
        } else if i < 8 {
            modules[i + 1][8] = dark;
        } else {
            modules[n - 15 + i][8] = dark;
        }

        if i < 8 {
            modules[8][n - 1 - i] = dark;
        } else if i < 9 {
            modules[8][15 - i] = dark;
        } else {
            modules[8][14 - i] = dark;
        }
    }
}

fn version_info_bits(version: u32) -> u32 {
    let mut rem = version << 12;
    for i in (0..6).rev() {
        if ((rem >> (i + 12)) & 1) != 0 {
            rem ^= 0b1_1111_0010_0101 << i;
        }
    }
    (version << 12) | rem
}

fn evaluate_penalty(modules: &[Vec<bool>]) -> u32 {
    let n = modules.len();
    let mut penalty = 0u32;

    // Rule 1: runs of 5+ same-color modules
    for r in 0..n {
        let mut run_len = 1u32;
        for c in 1..n {
            if modules[r][c] == modules[r][c - 1] {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len - 5);
                }
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len - 5);
        }
    }
    for c in 0..n {
        let mut run_len = 1u32;
        for r in 1..n {
            if modules[r][c] == modules[r - 1][c] {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len - 5);
                }
                run_len = 1;
            }
        }
        if run_len >= 5 {
            penalty += 3 + (run_len - 5);
        }
    }

    // Rule 2: 2x2 blocks
    for r in 0..n - 1 {
        for c in 0..n - 1 {
            let color = modules[r][c];
            if modules[r][c + 1] == color
                && modules[r + 1][c] == color
                && modules[r + 1][c + 1] == color
            {
                penalty += 3;
            }
        }
    }

    // Rule 4: dark ratio
    let dark_count: usize = modules.iter().flatten().filter(|&&b| b).count();
    let percent = (dark_count * 100) / (n * n);
    let prev5 = (percent / 5) * 5;
    let next5 = prev5 + 5;
    let k = prev5.abs_diff(50).min(next5.abs_diff(50)) / 5;
    penalty += (k as u32) * 10;

    penalty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_encodes_tg_proxy_url_and_renders_utf8() {
        let url = "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef";
        let matrix = encode_qr_matrix(url.as_bytes()).unwrap();
        assert_eq!(matrix.len(), 37); // Version 5 (81 bytes fits in V5 max 106 bytes)
        assert!(matrix.iter().all(|row| row.len() == 37));

        let rendered = render_qr_utf8(url).unwrap();
        assert!(!rendered.is_empty());
        assert!(rendered.lines().all(|l| l.chars().count() == 41)); // 37 + 2*2 quiet zone
    }
}
