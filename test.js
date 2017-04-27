const crypto = new (require("."));

const data = new Buffer("Test data");
const signature = new Buffer("761adaf94f5b5373a051c1a5225fbdacb035f984a5cb1db42307cd8ec16bed01b07171bedbce0a88699d05f50e0a10d0526cecea0abb38afbbf2c8763366ddd6b5213ba1389c261b7b5debb4c07af6c9bb95bf716a7be312c64a1ac3b7afae18e1c99a634dddc113a6de82d2a650a788b6b00c28051662eabc3fee18a03b80016136e6f941593c7f9fff027e686e9175f24fbc459d3882cc7080ffa138e2c55554fa949136f357a45a760897cc334b3fadc34b3a6588c23cab9bf1619e57342fcd84ab56c2f4bcdf274b0f8ffc43548abea3e9b0ed063ee3190d898e6a322cf11f0cea6bd90630b629d079a7592720ca020c0af4ed132107f00c724ddb688cc7", "hex");
const len = signature.length
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const jwk = {
    "kty": "RSA",
    "alg": "RS256",
    "ext": true,
    "key_ops": [
        "encrypt",
        "verify",
        "wrapKey"
    ],
    "e": "AQAB",
    "n": "oiYuUF9-krZQ88I5qJ1g1ziAUeH7RQ_SWowsFxb5bd-xE-yJ9IbgTskCI9rVbsiSper3OuUDLN1eB_BR6UP1_JiVN2Awo7-s1K81ZIjmnqqA3OH7Lqo3xVI9LLyeeGCnbzLBNnpWm6IbIxsfvW2DEAbbbAObF1NSs9ZudnAKACCx_L5vhd4umBK_nadC6Z3Gt6zcUs5lndj45pDF2i-Nfu13GLHzTs4Gt4GuFqEZpRC5WtwUdRNnnbIfvuLs9JEtI5GzFsWyC0u2jOhsb6LslojdENeyJ4qLgK9qAiQsFP2MbYQaVKUsPPsjVh6W_WQD2F2aN-WepZsG6t6TViRKrQ"
};

crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"])
    .then((key) => {
        return crypto.subtle.verify(alg, key, new_signature, data);
    })
    .then((ok) => {
        console.log("Verification:", ok);
    })
    .catch((err) => {
        console.error(err);
    })

/*

761adaf94f5b5373a051c1a5225fbdacb035f984a5cb1db42307cd8ec16bed01b07171bedbce0a88699d05f50e0a10d0526cecea0abb38afbbf2c8763366ddd6b5213ba1389c261b7b5debb4c07af6c9bb95bf716a7be312c64a1ac3b7afae18e1c99a634dddc113a6de82d2a650a788b6b00c28051662eabc3fee18a03b80016136e6f941593c7f9fff027e686e9175f24fbc459d3882cc7080ffa138e2c55554fa949136f357a45a760897cc334b3fadc34b3a6588c23cab9bf1619e57342fcd84ab56c2f4bcdf274b0f8ffc43548abea3e9b0ed063ee3190d898e6a322cf11f0cea6bd90630b629d079a7592720ca020c0af4ed132107f00c724ddb688cc7

761adaf94f5b5373a051c1a5225fbdacb035f984a5cb1db42307cd8ec16bed01b07171bedbce0a88699d05f50e0a10d0526cecea0abb38afbbf2c8763366ddd6b5213ba1389c261b7b5debb4c07af6c9bb95bf716a7be312c64a1ac3b7afae18e1c99a634dddc113a6de82d2a650a788b6b00c28051662eabc3fee18a03b80016136e6f941593c7f9fff027e686e9175f24fbc459d3882cc7080ffa138e2c55554fa949136f357a45a760897cc334b3fadc34b3a6588c23cab9bf1619e57342fcd84ab56c2f4bcdf274b0f8ffc43548abea3e9b0ed063ee3190d898e6a322cf11f0cea6bd90630b629d079a7592720ca020c0af4ed132107f00c724ddb688cc7

*/