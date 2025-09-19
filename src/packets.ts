import base85 from "base85";

export type OutcomingPacket = {
    type: "encInit",
    host: string,
    data: Buffer,
    reqseq: number
} | {
    type: "encData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "reqData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "req",
    reqseq: number,
    hostname: string,
    port: number,
    path: string,
    method: string,
    headers: [string, string][],
    body: Buffer
} | {
    type: "key",
    key: object
};
export type IncomingPacket = {
    type: "encData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "resData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "res",
    reqseq: number,
    status: number,
    statusText: string,
    headers: [string, string][],
    body: Buffer
} | {
    type: "key",
    key: object
};

export const decodePacket = (text: string): IncomingPacket | false => {
    if(text.length < 1) return false;
    const type = text[0];
    text = text.slice(1);

    let obj = {} as IncomingPacket;
    switch(type) {
    case "d":
        obj.type = "encData";
        break;
    case "D":
        obj.type = "resData";
        break;
    case "r":
        obj.type = "res";
        break;
    case "k":
        obj.type = "key";
        break;
    default:
        return false;
    }
    // i hate typescript
    const rest = text.split("~").map(x => base85.decode(x, "z85pad" as base85.Base85Encoding)) as Buffer[];
    if((rest as (Buffer | false)[]).includes(false)) return false;
    switch(obj.type) {
    case "encData":
        obj.reqseq = rest[0].readUInt32BE();
        obj.datseq = rest[1].readUInt32BE();
        obj.data = rest[2];
        break;
    case "resData":
        obj.reqseq = rest[0].readUInt32BE();
        obj.datseq = rest[1].readUInt32BE();
        obj.data = rest[2];
        break;
    case "res":
        obj.reqseq = rest[0].readUInt32BE();
        obj.status = rest[1].readUInt16BE();
        obj.statusText = rest[2].toString();
        obj.headers = rest[3].toString().split("\n").map(x => {
            const ind = x.indexOf(":");
            return [x.slice(0, ind), x.slice(ind + 1)];
        });
        obj.body = rest[4];
        break;
    case "key":
        obj.key = JSON.parse(rest[0].toString());
        break;
    }

    return obj;
};

export const encodePacket = (packet: OutcomingPacket): string => {
    let out: string = "";
    let parts: Buffer[] = [];
    switch(packet.type) {
    case "encData":
        out = "d";
        const reqseq = Buffer.alloc(4); reqseq.writeUInt32BE(packet.reqseq);
        const datseq = Buffer.alloc(4); datseq.writeUInt32BE(packet.datseq);
        parts.push(reqseq, datseq, packet.data);
        break;
    case "key":
        out = "k";
        parts.push(Buffer.from(JSON.stringify(packet.key)));
        break;
    case "req":
        out = "r";
        // why can't i use the same variable name multiple times lol
        const reqseq2 = Buffer.alloc(4); reqseq2.writeUInt32BE(packet.reqseq);
        const port = Buffer.alloc(2); port.writeUInt16BE(packet.port);
        parts.push(reqseq2, Buffer.from(packet.hostname), port, Buffer.from(packet.path), Buffer.from(packet.method), Buffer.from(packet.headers.map(x => x.join(":")).join("\n")), packet.body);
        break;
    case "encInit":
        out = "i";
        const reqseq3 = Buffer.alloc(4); reqseq3.writeUInt32BE(packet.reqseq);
        parts.push(reqseq3, Buffer.from(packet.host), packet.data);
        break;
    case "reqData":
        out = "D";
        const reqseq4 = Buffer.alloc(4); reqseq4.writeUInt32BE(packet.reqseq);
        const datseq2 = Buffer.alloc(4); datseq2.writeUInt32BE(packet.datseq);
        parts.push(reqseq4, datseq2, packet.data);
        break;
    }
    out += parts.map(x => base85.encode(x, "z85pad" as base85.Base85Encoding)).join("~");
    return out;
};