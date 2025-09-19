import base85 from "base85";

export const genKeypair = async () => {
    return await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
};

export const deriveSharedKey = async (myPrivateKey: CryptoKey, theirPublicKey: CryptoKey) => {
    return await crypto.subtle.deriveKey(
        { name: "ECDH", public: theirPublicKey },
        myPrivateKey,
        { name: "AES-GCM", length: 256 },
        true, ["encrypt", "decrypt"]
    );
};
export const importKey = async (bytes: ArrayBuffer | string) => {
    if(typeof bytes === "string")
        bytes = new TextEncoder().encode(bytes).buffer;
    return await crypto.subtle.importKey(
        "raw",
        bytes,
        { name: "AES-GCM" },
        false, ["encrypt", "decrypt"]
    );
};

export const u8ToB85 = (buf: Uint8Array) => base85.encode(Buffer.from(buf), "z85pad" as base85.Base85Encoding);
export const b85ToU8 = (b85: string) => new Uint8Array(base85.decode(b85, "z85pad" as base85.Base85Encoding) || Buffer.alloc(0));

export const encrypt = async (msg: Buffer, key: CryptoKey) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return [u8ToB85(iv),
        u8ToB85(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, msg)))];
};
export const decrypt = async (msg: string, iv: string, key: CryptoKey) => {
    const u8msg = b85ToU8(msg);
    const u8iv = b85ToU8(iv);
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8iv }, key, u8msg.buffer);
};