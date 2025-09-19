import http from "http";
import { Client } from "./max";
import * as storage from "./storage";
import { randomUUID } from "crypto";
import { question } from "readline-sync";
import { decrypt, deriveSharedKey, encrypt, genKeypair } from "./crypto";
import { decodePacket, encodePacket, IncomingPacket, OutcomingPacket } from "./packets";

process.on("uncaughtException", err => console.error(err));
process.on("unhandledRejection", err => console.error(err));

const keys = await genKeypair();
let globalSecret: CryptoKey;

const client = new Client();
await client.init();

let authData = storage.getAuthData();
if(!authData.id || !authData.token) {
    authData.id = randomUUID();
    await client.presentDevice(authData.id);
    const phone = question("phone: ");
    const verifyToken = await client.requestCode(phone);
    const code = question("sms code: ");
    authData.token = await client.presentCode(verifyToken, code);
    if(authData.token === "") {
        console.error("wrong code!");
        process.exit(1);
    }
    storage.setAuthData(authData.id, authData.token);
} else {
    await client.presentDevice(authData.id);
}
let afterTokenData = await client.presentToken(authData.token);
console.log(`Logged in as ${afterTokenData.profile.contact.names[0].name}`);

const chatID = parseInt(process.env.CHAT_ID || question("chat id: "));

type ProxyRequest = {
    type: "http" | "https",
    reqseq: number,
    cb: (data: IncomingPacket) => void
};
let lastReqSeq = 0;
const proxyRequests: ProxyRequest[] = [];

const getEnc = async (packet: string) => {
    const enc = await encrypt(Buffer.from(packet), globalSecret);
    return `s${enc[0]}~${enc[1]}`;
}

client.addMessageHandler(async packet => {
    if(packet.opcode === 1 || packet.cmd === 3) {
        await client.reopen();
        await client.presentDevice(authData.id);
        afterTokenData = await client.presentToken(authData.token);
        return;
    }
    if(packet.opcode !== 128) return;
    const { message, chatId: chatID } = packet.payload as { message: { sender: number, text: string, id: string }, chatId: number };

    if(message.text[0] === "k") {
        // key packet, unencrypted
        const packet = decodePacket(message.text);
        if(!packet || packet.type !== "key") return;
        const theirPublicKey = await crypto.subtle.importKey("jwk", packet.key, { name: "ECDH", namedCurve: "P-256" }, true, []);
        globalSecret = await deriveSharedKey(keys.privateKey, theirPublicKey);
        
    } else if(message.text[0] === "s") {
        // other packet types, encrypted
        const parts = message.text.slice(1).split("~");
        const dec = await decrypt(parts[1], parts[0], globalSecret);
        const packet = decodePacket(Buffer.from(dec).toString());
        if(!packet) return;

        if(packet.type === "key") return;
        proxyRequests.find(x => x.reqseq === packet.reqseq)?.cb?.(packet);
    }
});

// chatgpt helped me a bit with this
const proxyServer = http.createServer(async (req, res) => {
    const parsed = new URL(req.url || "");
    console.log(req.url);
    const reqseq = lastReqSeq++;
    let datseq = 0;
    proxyRequests.push({
        type: "http",
        reqseq,
        cb: (packet: IncomingPacket) => {
            if(packet.type === "resData") {
                if(packet.data.length === 0) res.end();
                else res.write(packet.data);
            } else if(packet.type === "res") {
                res.writeHead(packet.status, packet.statusText, packet.headers.flat());
            }
        }
    });
    const packet: OutcomingPacket = {
        type: "req",
        reqseq,
        hostname: parsed.hostname,
        port: parseInt(parsed.port || "80"),
        path: parsed.pathname + parsed.search,
        method: req.method as string,
        headers: req.rawHeaders.map((x, i, a) => i % 2 === 0 ? [x, a[i + 1]] : null).filter(x => x !== null) as [string, string][],
        body: Buffer.alloc(0)
    };
    await client.sendMessage(chatID, await getEnc(encodePacket(packet)));
    req.on("data", async data => {
        const packet: OutcomingPacket = {
            type: "reqData",
            reqseq,
            datseq: datseq++,
            data
        };
        await client.sendMessage(chatID, await getEnc(encodePacket(packet)));
    });
});
proxyServer.on("connect", async (req, sock, head) => {
    console.log(req.url);
    const reqseq = lastReqSeq++;
    let datseq = 0;

    proxyRequests.push({
        type: "https",
        reqseq,
        cb: (packet: IncomingPacket) => {
            if(packet.type !== "encData") return;
            if(packet.data.length === 0) sock.end();
            else sock.write(packet.data);
        }
    });
    const packet: OutcomingPacket = {
        type: "encInit",
        reqseq,
        host: req.url as string,
        data: Buffer.alloc(0)
    };
    await client.sendMessage(chatID, await getEnc(encodePacket(packet)));
    sock.on("data", async data => {
        const packet: OutcomingPacket = {
            type: "encData",
            reqseq,
            datseq: datseq++,
            data
        };
        await client.sendMessage(chatID, await getEnc(encodePacket(packet)));
    });
    sock.write(`HTTP/1.1 200 Connection Established
Proxy-agent: maxnet

`);
});

proxyServer.listen(10432, "127.0.0.1");

await client.sendMessage(chatID, encodePacket({
    type: "key",
    key: await crypto.subtle.exportKey("jwk", keys.publicKey)
}));