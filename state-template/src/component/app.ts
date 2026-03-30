import { TitleComponent } from "./title";
import { ReasonComponent } from "./reason";

export interface ReputationState {
    state: string | "warn" | "block";
    warn: number;
    block: number;
    ip: number;
    asn: number;
    ua: number;
    uri: number;
    country: number;
    status: number;
    perIp: number;
    perNet: number;
    perASN: number;
}

export class AppComponent {
    constructor() {
        this.initialize();
    }

    private cmpFn(rep: number, warn: number, block: number) {
        const neg = block < warn;
        return neg ? rep <= warn || rep <= block : rep >= warn || rep >= block;
    }

    private initialize() {
        const tCmp = new TitleComponent();
        const rCmp = new ReasonComponent();
        const rsElm = document.getElementById("repudiator-state");

        if (rsElm) {
            try {
                const repState: ReputationState = JSON.parse(rsElm.innerText);

                if (repState.state === "warn") {
                    tCmp.setTitle("Request was throttled");
                } else {
                    tCmp.setTitle("Request was blocked");
                }

                if (this.cmpFn(repState.ip, repState.warn, repState.block) || this.cmpFn(repState.perIp, repState.warn, repState.block)) {
                    rCmp.addReason("IP address", "Too many requests from your IP address within a specific time period.");
                }
                if (this.cmpFn(repState.ip, repState.warn, repState.block) || this.cmpFn(repState.perASN, repState.warn, repState.block)) {
                    rCmp.addReason("ASN block", "Too many requests from ASN block within a specific time period.");
                }
                if (this.cmpFn(repState.perNet, repState.warn, repState.block)) {
                    rCmp.addReason("Network block", "Too many requests from network block within a specific time period.");
                }
                if (this.cmpFn(repState.ua, repState.warn, repState.block)) {
                    rCmp.addReason("UserAgent", "We have detected an unwanted user agent. This can happen if you are an unwanted bot or are using a very old browser and/or an outdated operating system.");
                }
                if (this.cmpFn(repState.uri, repState.warn, repState.block)) {
                    rCmp.addReason("URI", "You request a disallowed URI like /etc/passwd.");
                }
                if (this.cmpFn(repState.country, repState.warn, repState.block)) {
                    rCmp.addReason("Country", "Your country is defined in our unwanted list.");
                }
                if (this.cmpFn(repState.status, repState.warn, repState.block)) {
                    rCmp.addReason("HTTP status code", "Too many requests that generate a specific HTTP status code on our web services.");
                }

                rCmp.outputReasons();
            } catch (e) {
                if (e instanceof Error) {
                    tCmp.setTitle(e.name);
                    rCmp.addReason(e.message, (e.stack || "").replace(/\n/g, "<br>"));
                    rCmp.outputReasons();
                }
            }
        }
    }
}