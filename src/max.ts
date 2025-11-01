// Most of the code taken from https://github.com/Milk-Cool/MAXe2e
// TODO: make this a separate module maybe? we don't want suplicated code in server AND client

const WS_URL = "https://ws-api.oneme.ru/websocket";
const USER_AGENT = {
    appVersion: "25.9.12",
    deviceLocale: "en",
    deviceName: "Chrome",
    deviceType: "WEB",
    headerUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    locale: "ru",
    osVersion: "Linux",
    screen: "1080x1920 1.0x",
    timezone: "Europe/Moscow"
};

type Packet = {
    ver: number;
    cmd: 0 | 1 | 3;
    seq: number;
    opcode: number;
    payload: object | null;
};
export type Chat = {
    title: string,
    id: number
} & {
    participants: Record<string, number>,
    id: number
};
export type PresentTokenReturn = {
    profile: Profile,
    chats: Chat[];
};

export type Profile = {
    contact: Contact
};

export type Contact = {
    id: number;
    names: {
        name: string;
        firstName: string;
        lastName: string;
    }[]
};
export type Contacts = {
    contacts: Contact[];
}

export type Message = {
    id: string;
    sender: number;
    text: string;
    time: number;
};
export type Messages = {
    messages: Message[]
};

export class Client {
    private ver = 11;

    private seq: number = 0;
    private ws: WebSocket;
    private interval: ReturnType<typeof setInterval> | null = null;

    private handler: ((packet: Packet) => void) | null = null;

    constructor() {
        this.ws = new WebSocket(WS_URL, {
            // @ts-ignore
            headers: {
                "Origin": "https://web.max.ru"
            }
        });
    }
    async init() {
        this.ws.addEventListener("message", event => {
            const incoming = JSON.parse(event.data) as Packet;
            if(incoming.cmd !== 0 && incoming.cmd !== 3) return;
            if(this.handler !== null) this.handler(incoming);
        });
        await new Promise(resolve => this.ws.addEventListener("open", resolve));
        if(this.interval !== null) clearInterval(this.interval);
        this.interval = setInterval(async () => this.ping(), 10000);
    }

    private constructPacket(opcode: number, payload: object | null, seq: number = -1, direction: 0 | 1 = 0): Packet {
        return { ver: this.ver, cmd: direction, seq: seq === -1 ? this.seq++ : seq, opcode, payload };
    }
    private async sendPacket(packet: Packet): Promise<Packet>;
    private async sendPacket(packet: Packet, waitForReply: false): Promise<null>;
    private async sendPacket(packet: Packet, waitForReply: boolean = true): Promise<Packet | null> {
        const str = JSON.stringify(packet);
        this.ws.send(str);
        let ret: Packet | null = null;
        if(waitForReply) await new Promise(resolve => {
            const handler = (event: MessageEvent) => {
                const incoming = JSON.parse(event.data) as Packet;
                if(incoming.cmd !== 1) return;
                if(incoming.seq !== packet.seq) return;
                this.ws.removeEventListener("message", handler);
                ret = incoming;
                resolve(null);
            };
            this.ws.addEventListener("message", handler);
        });
        return ret;
    }
    private async msg(opcode: number, payload: object | null): Promise<Packet>;
    private async msg(opcode: number, payload: object | null, waitForReply: false): Promise<null>;
    private async msg(opcode: number, payload: object | null, waitForReply: boolean = true): Promise<Packet | null> {
        const packet = this.constructPacket(opcode, payload);
        // stupid typescript
        if(waitForReply) return await this.sendPacket(packet);
        else return await this.sendPacket(packet, false);
    }

    addMessageHandler(handler: (packet: Packet) => void) {
        this.handler = handler;
    }

    async presentDevice(deviceID) {
        await this.msg(6, {
            userAgent: USER_AGENT,
            deviceId: deviceID
        });
    }
    async requestCode(phone: string): Promise<string> {
        const res = await this.msg(17, {
            phone,
            type: "START_AUTH",
            language: "ru"
        });
        const { token } = res.payload as { token: string };
        return token;
    }
    async presentCode(token: string, code: string): Promise<string> {
        const res = await this.msg(18, {
            token,
            verifyCode: code,
            authTokenType: "CHECK_CODE"
        });
        return (res?.payload as { tokenAttrs?: { LOGIN?: { token?: string } } })?.tokenAttrs?.LOGIN?.token ?? "";
    }

    async presentToken(token: string): Promise<PresentTokenReturn> {
        return (await this.msg(19, {
            interactive: true,
            token,
            chatsSync: 0,
            contactsSync: 0,
            presenceSync: 0,
            draftsSync: 0,
            chatsCount: 40
        })).payload as PresentTokenReturn;
    }

    async sendMessage(chatID: number, message: string) {
        await this.msg(64, {
            chatId: chatID,
            message: {
                text: message,
                cid: Math.floor(Math.random() * Number.MAX_SAFE_INTEGER),
                elements: [],
                attaches: []
            },
            notify: true
        });
    }

    async getContacts(...ids: number[]): Promise<Contacts | null> {
        if(ids.find(x => x === null)) return null;
        return (await this.msg(32, { contactIds: ids })).payload as Contacts;
    }

    async respondSeenMessage(seq: number, chatID: number, messageID: string) {
        await this.sendPacket(this.constructPacket(128, {
            chatId: chatID,
            messageId: messageID
        }, seq, 1), false);
    }

    async resolvePhoneNumber(phone: string) {
        return ((await this.msg(46, {
            phone
        })).payload as { contact: Contact }).contact;
    }

    close() {
        this.ws.close();
    }

    async reopen() {
        if(this.ws.readyState === 1) this.ws.close();
        this.ws = new WebSocket(WS_URL);
        await this.init();
    }

    async getMessages(chatID: number, n: number = 100) {
        return (await this.msg(49, {
            backward: n,
            forward: 0,
            chatId: chatID,
            from: Date.now(),
            getMessages: true
        })).payload as Messages;
    }

    private async ping() {
        await this.msg(1, { interactive: true }, false);
    }
}