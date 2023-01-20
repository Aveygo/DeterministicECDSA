# DeterministicECDSA

Deterministic ECDSA keys with WebCrypto.

After importing main.js, the main function that generates the token is generate_jwk()

Example usage:

```
async function main() {
    let seed = await crypto.getRandomValues(new Uint32Array(1))[0];
    var key = await window.crypto.subtle.importKey(
            "jwk",
            await generate_jwk(BigInt(seed)),
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["sign"]
        );
    console.log(key);
}
```
