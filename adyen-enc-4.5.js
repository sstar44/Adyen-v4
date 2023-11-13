/*
 * Adyen 4.5.0 encryption by github.com/levi-nz
 *
 * This code is a rough implementation and can be improved in some places.
 * Read comments throughout the code for more information.
 */

const jose = require('node-jose');

// Parse the key from the string found in securedFields.html ("10001|...")
async function parseKey(t) {
    // These two functions can probably be replaced with something cleaner
    // to: URL-safe base64 encode?
    // ro: hex decode
    function to(e) {
        return function(e) {
            var t = e;
            for (var r = [], n = 0; n < t.length; n += 32768)
                r.push(String.fromCharCode.apply(null, t.subarray(n, n + 32768)));
            return btoa(r.join(""))
        }(e).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
    }

    function ro(e) {
        if (!e)
            return new Uint8Array(0);
        e.length % 2 == 1 && (e = "0" + e);
        for (var t = e.length / 2, r = new Uint8Array(t), n = 0; n < t; n++)
            r[n] = parseInt(e.substr(2 * n, 2), 16);
        return r
    }

    const r = t.split("|"); // Key parts
    const n = r[0]; // Exponent
    const o = r[1]; // RSA public key
    const i = ro(n);
    const a = ro(o);
    const c = to(i);
    const s = to(a);

    return jose.JWK.asKey({
        kty: "RSA",
        kid: "asf-key", // kid used in Adyen script
        e: c,
        n: s
    });
}

// Encrypt fieldName with value and generationTime with the given pubKey
// Valid field names:
// - number
// - expiryMonth
// - expiryYear
// - cvc
async function encrypt(pubKey, fieldName, value, generationTime) {
    // ISO string without milliseconds
    const formattedGenerationTime = generationTime.toISOString().split('.')[0]+"Z";

    let data;
    switch (fieldName) {
        case "number":
            data = {
                "number": value,
                "activate": "3",
                "deactivate": "1",
                "generationtime": formattedGenerationTime,
                "numberBind": "1",
                "numberFieldBlurCount": "1",
                "numberFieldClickCount": "1",
                "numberFieldFocusCount": "3",
                "numberFieldKeyCount": "2",
                "numberFieldLog": "fo@5956,cl@5960,bl@5973,fo@6155,fo@6155,Md@6171,KL@6173,pa@6173",
                "numberFieldPasteCount": "1",
                "referrer": "https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_DY4VMYQL5ZHXXE5NLG4RA5PYKYWDYAU2/4.5.0/securedFields.html?type=card&d=aHR0cHM6Ly9jaGVsc2VhZmMuM2RkaWdpdGFsdmVudWUuY29t"
            };
            break;

        case "expiryMonth":
            data = {
                "expiryMonth": value,
                "generationtime": formattedGenerationTime
            };
            break;

        case "expiryYear":
            data = {
                "expiryYear": value,
                "generationtime": formattedGenerationTime
            };
            break;

        case "cvc":
            data = {
                "activate": "1",
                "cvc": value,
                "cvcBind": "1",
                "cvcFieldClickCount": "1",
                "cvcFieldFocusCount": "2",
                "cvcFieldKeyCount": "4",
                "cvcFieldLog": "fo@20328,fo@20328,cl@20329,KN@20344,KN@20347,KN@20349,KN@20351",
                "generationtime": formattedGenerationTime,
                "referrer": "https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_DY4VMYQL5ZHXXE5NLG4RA5PYKYWDYAU2/4.5.0/securedFields.html?type=card&d=aHR0cHM6Ly9jaGVsc2VhZmMuM2RkaWdpdGFsdmVudWUuY29t"
            };
            break;

        default:
            throw new Error("Invalid fieldName " + fieldName);
    }

    return jose.JWE.createEncrypt(
        {
            format: "compact",
            contentAlg: "A256CBC-HS512",
            fields: {
                alg: "RSA-OAEP",
                enc: "A256CBC-HS512",
                version: "1" // additional field added by Adyen
            }
        },
        {key: pubKey, reference: false} // don't include "kid" field in header
    )
        .update(JSON.stringify(data))
        .final();
}

(async () => {
    // Obtain key from securedFields.html
    const key = await parseKey("10001|E9299A45B34AE878855F3E66136B461664F519E85F36E59B505CD6590311FE96BAF50830BED460FE6EB8AD39B3E4BFCF5028A33A64C518E3BC13F23E49CE9C68B13A3ED9BB9233C166A7572755E62CB67AAF7A6AFC1070CAD7FF3F6FD8C070168FC6ED31E81F3DE10A93D6A9494F9D24900F1499D95264E66E3DC357B4628E02A6DF0ED37196539309AB0B1EA7EEB2BD67452B16289452D617C687867981C3570E0C43C51EB273154011D53F09B2B2E1AAD41B13B686A861D2C095DFEA258AD589AE482CAF9B05EFFF1C16EF182D67CA459B6EBD00E63F170307B56237A6C8AE593EFAD9E58AEC7D560B41B3412DD7D5E64B76BFEF75354DC52BD2138B77F279");//await jose.JWK.createKey("RSA", 2048);

    // generationTime should be the same for the entire object
    // Note: the "live_" string needs to be replaced with the key
    // of the site you're using, you should probably add it as a
    // parameter to the encrypt function.
    //
    // encrypt function doesn't support objects over individual fields,
    // but can be added easily.
    const generationTime = new Date;
    // Encrypt data
    const data = await Promise.all([
        encrypt(key, "number", "3700 000000 00002", generationTime),
        encrypt(key, "expiryMonth", "03", generationTime),
        encrypt(key, "expiryYear", "2030", generationTime),
        encrypt(key, "cvc", "7474", generationTime)
    ]);

    // Print object (this may differ on some sites)
    console.log(JSON.stringify({
        "type": "scheme",
        holderName: "",
        "encryptedCardNumber": data[0],
        "encryptedSecurityCode": data[3],
        "encryptedExpiryYear": data[2],
        "encryptedExpiryMonth": data[1],
        // Get this from the HTTP request
        "checkoutAttemptId": "e1d2565b-49bc-4915-9366-3466088d327e16894362531752950F9D0E62A4448B2F8C1AA01EA010CFEDB377CADEC53EC9F67333B14A8FF19"
    }));
})();