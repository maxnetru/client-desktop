import { Client } from "./max";

const TIMEOUT_TIME = 400;

export class OutcomingAccumulator {
    private packets: { n: number, enc: string }[] = [];
    private timeout: number | null = null;
    constructor(private client: Client, private chatID: number) {}
    addPacket(n: number, enc: string) {
        if(this.timeout !== null) clearTimeout(this.timeout);
        setTimeout(async () => await this.send(), TIMEOUT_TIME);
        this.packets.push({ n, enc });
    }
    private async send() {
        // reset immediately
        const packets = [...this.packets];
        this.packets = [];
        this.timeout = null;

        packets.sort((a, b) => a.n - b.n);
        for(const packet of packets)
            await this.client.sendMessage(this.chatID, packet.enc);
    }
}
export class IncomingAccumulator {
    private packets: { n: number, data: Buffer }[] = [];
    private timeout: number | null = null;
    constructor(private cb: (data: Buffer) => any) {}
    addPacket(n: number, data: Buffer) {
        if(this.timeout !== null) clearTimeout(this.timeout);
        setTimeout(async () => await this.send(), TIMEOUT_TIME);
        this.packets.push({ n, data });
    }
    private async send() {
        // reset immediately
        const packets = [...this.packets];
        this.packets = [];
        this.timeout = null;

        packets.sort((a, b) => a.n - b.n);
        for(const packet of packets) {
            this.cb(packet.data);
        }
    }
}