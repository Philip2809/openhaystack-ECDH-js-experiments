// Change this based on your data!
const privateKeyInput = ""
const payloadInput = ""


// fix curves
const start = Date.now();
set_ec_params("secp224r1");
const curve = get_curve();
const G = get_G(curve);


// Get public key
const privateKey = Uint8Array.from(atob(privateKeyInput), char => char.charCodeAt(0));
const publicKey = G.multiply(new BigInteger(privateKey));
const publicKeyXByteArrayUnsigned = publicKey.getX().toBigInteger().toByteArray();
const publicKeyXByteArray = getCorrectedBytes(publicKeyXByteArrayUnsigned);

async function SHA256Hash(val) {
    const hash = await crypto.subtle.digest('SHA-256', val);
    return new Uint8Array(hash);
}

const hashValue = val =>
    crypto.subtle
      .digest('SHA-256', val)
      .then(buffer => {
        const arr1 = new Uint8Array(buffer);
        return base64Encode(arr1);
});


console.log('adv key:', base64Encode(publicKeyXByteArray));
console.log('mac address:', getMacAddress(publicKeyXByteArray));
SHA256Hash(publicKeyXByteArray).then(hashed => console.log('hashed adv key:', base64Encode(hashed)));

function getMacAddress(byteArray) {
    const firstByte = byteArray[0] | 0b11000000;
    const macAddress = [firstByte, ...byteArray.slice(1, 6)];
    return macAddress.map(byte => byte.toString(16).toUpperCase().padStart(2, '0')).join(':');
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
      return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

function getCorrectedBytes(inputArray) {
    // Convert the input array to Uint8Array, correcting any negative values
    return new Uint8Array(inputArray.map(value => (value < 0 ? 256 + value : value)));
}

function base64Encode(bytes) {
    // Convert Uint8Array to a binary string
    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    
    // Encode the binary string in Base64
    return btoa(binary);
}


async function kdf(sharedKey, ephKey, counter = 1) {
    // Convert counter to 4 bytes (big-endian)
    const counterArray = new Uint8Array(4);
    new DataView(counterArray.buffer).setUint32(0, counter, false); // false for big-endian

    // Concatenate shared_key, counter data, and eph_key
    const data = new Uint8Array(sharedKey.length + counterArray.length + ephKey.length);
    data.set(sharedKey, 0);
    data.set(counterArray, sharedKey.length);
    data.set(ephKey, sharedKey.length + counterArray.length);

    // Compute SHA-256 hash of the concatenated data
    const digest = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(digest); // Return hash as byte array
}


let payload_bytearray = Uint8Array.from(atob(payloadInput), char => char.charCodeAt(0));

if (payload_bytearray.length > 88) {
    const part1 = payload_bytearray.slice(0, 4);
    const part2 = payload_bytearray.slice(5, 89);
    payload_bytearray = new Uint8Array(part1.length + part2.length);
    payload_bytearray.set(part1, 0);
    payload_bytearray.set(part2, part1.length);
}


console.log('timestamp:', convertArrayToBigint(payload_bytearray.slice(0, 4)).toString());
console.log('confidance:', payload_bytearray[4]);

const eph_key = payload_bytearray.slice(5, 62);
const pubx = eph_key.slice(1, 29);
const puby = eph_key.slice(29, 57);

function convertArrayToBigint(array) {
    let bigint = BigInt(0);
    for (let byte of array) {
        bigint = (bigint << BigInt(8)) + BigInt(byte);
    }
    return bigint.toString();
}

var P = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(convertArrayToBigint(pubx))),
    curve.fromBigInteger(new BigInteger(convertArrayToBigint(puby)))
);
var a = new BigInteger(convertArrayToBigint(privateKey));
var S = P.multiply(a);

// Sometimes the sharedbytes comes with an extra 0 at the beginning, so we remove it, donno why, maybe check if this code is used more?
let shared_bytes = getCorrectedBytes(S.getX().toBigInteger().toByteArray());
if (shared_bytes.at(0) === 0) shared_bytes = shared_bytes.slice(1);

kdf(shared_bytes, eph_key).then(async symmetricKey => {
    const decryptionKeyBytes = symmetricKey.slice(0, 16);
    const iv = symmetricKey.slice(16, 32);

    const enc_data = payload_bytearray.slice(62, 72);
    const tag = payload_bytearray.slice(72, 88);

    // combine enc_data and tag, this is how the decryption function expects the data
    const enc_data_tag = new Uint8Array(enc_data.length + tag.length);
    enc_data_tag.set(enc_data, 0);
    enc_data_tag.set(tag, enc_data.length);

    const key = await crypto.subtle.importKey(
        "raw",
        decryptionKeyBytes.buffer,
        "AES-GCM",
        true,
        ["decrypt"]
    );

    try {
        // Perform decryption
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv.buffer,
            },
            key,
            enc_data_tag.buffer
        );

        const data = new Uint8Array(decryptedData);
        const latitude  = new DataView(data.slice(0, 4).buffer).getUint32(0, false) / 10000000.0;
        const longitude  = new DataView(data.slice(4, 8).buffer).getUint32(0, false) / 10000000.0;
        const horizontal_acc  = data[8];
        const status  = data[9]
        
        console.log('encrypted data:', latitude, longitude, horizontal_acc, status);
        const finish = Date.now();
        console.log(`Time taken: ${finish - start}ms`); 

        return new Uint8Array(decryptedData); // Decrypted data in byte array
    } catch (e) {
        console.error("Decryption failed:", e);
        return null;
    }
});
