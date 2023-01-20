// Compressed/Simplified revision of jwkGenerator

class Point { constructor(x, y) { this.x = x; this.y = y; }}

// Curve parameters for p-256, taken from https://neuromancer.sk/std/nist
// Web-crypto only supports p-256, p-384, and p-512, so we are limited to those.
const P = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
const A = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
const G = new Point(BigInt("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"), BigInt("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
const INF = new Point(0n, 0n);

// Base64url length, (p-256 -> 43, p-384 -> 64, p-512 -> 86)
const base64url_len = 43;

// Mod function, but works with negative numbers and limited to P as 
// that is the only modulus we will be using 
function mod_p(n) { return ((n % P) + P) % P; }

// Length of a string in bytes
function length(n) { return (new TextEncoder().encode(n)).length; }

function eucl_algo(a) {
    // Extended Euclidean Algorithm, returns modular inverse of a
    // Adapted to carry sign of a and mods result to P.
    var sign_a = (a < 0) ? -1n : 1n, x = 0n, y = 1n, u = 1n, v = 0n, b = P, q, r, m, n;
    a = (a < 0n) ? -a : a; // Absolute value of a

    while (a !== 0n) {
        q = b / a;
        r = b % a;
        m = x - u * q;
        n = y - v * q;
        b = a; a = r;
        x = u; y = v;
        u = m; v = n;
    }
    return mod_p(sign_a * x);
}

function p_add(p, q) {
    // Point addition, returns p + q
    if (p === INF) { return q; }
    if (q === INF) { return p; }
    if (p.x === q.x && p.y !== q.y) { return INF;}
    let m;
    if (p.x === q.x && p.y === q.y) {
        m = (3n * p.x * p.x + A) * eucl_algo(2n * p.y);
    } else {
        m = (p.y - q.y) * eucl_algo(p.x - q.x);
    }
    let x = mod_p((m * m - p.x - q.x));
    let y = mod_p((-(m*(x - p.x) + p.y)));
    return new Point(x, y);
}

function int2bytes(n) {
    // Convert a BigInt to a Uint8Array for hashing
    let bytes = new Uint8Array(n.toString(16).length / 2);
    for (let i = 0; i < n.toString(16).length; i += 2) {
        bytes[i / 2] = parseInt(n.toString(16).substr(i, 2), 16);
    }
    return bytes;
}

function int2burl(n) {
    // Convert a BigInt to a base64url string for use in jwk
    let base64 = btoa(String.fromCharCode(...int2bytes(n)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function calculate_jwk_result(k) {
    // Double and add algorithm, returns final jwk
    let result = INF, append = G, seed = k;
    while (k) {
        if (k & 1n) { result = p_add(result, append); }
        append = p_add(append, append);
        k = k >> 1n;
    }
    return {"crv": "P-256", "d": int2burl(seed), "ext":true, "key_ops":["sign"], "kty":"EC", "x":int2burl(result.x),"y":int2burl(result.y)};
}

async function generate_jwk(seed) {
    // Generate a jwk from a BigInt seed.
    let jwk = calculate_jwk_result(seed);

    // Web-Crypto only accepts keys with a base64url length of base64url_len bytes (no padding...)
    while (length(jwk.d) < base64url_len || length(jwk.x) < base64url_len || length(jwk.y) < base64url_len) {
        // If invalid, hash the seed (to maintain determinism) and use that as the new seed.
        let hash = new Uint8Array(await crypto.subtle.digest('SHA-256', int2bytes(seed))); 
        seed = BigInt('0x' + Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));
        jwk = calculate_jwk_result(seed);
    }

    return jwk;
}
