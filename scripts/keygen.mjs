const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const { kty, crv, x, y, d } = await crypto.subtle.exportKey("jwk", privateKey);
console.log(JSON.stringify({ kty, crv, x, y, d, kid: crypto.randomUUID().slice(0, 8) }));
