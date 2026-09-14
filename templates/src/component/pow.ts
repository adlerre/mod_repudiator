import { I18N } from "./i18n";

export interface POWPayload {
    challenge: string;
    difficulty: number;
    powURI?: string;
    uri?: string;
}

export class POWComponent {

    constructor() {
        this.initialize();
    }

    sha256Pure(bytes: Uint8Array) {
        const K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
        const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

        const len = bytes.length;
        let padLen = len + 1;
        while (padLen % 64 !== 56) padLen++;
        padLen += 8;

        const padded = new Uint8Array(padLen);
        padded.set(bytes);
        padded[len] = 0x80;
        const dv = new DataView(padded.buffer);
        dv.setUint32(padLen - 4, (len * 8) >>> 0, false);
        dv.setUint32(padLen - 8, Math.floor(len * 8 / 0x100000000), false);

        for (let i = 0; i < padLen; i += 64) {
            const W = new Array(64);
            for (let t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4, false);
            for (let t = 16; t < 64; t++) {
                const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
                const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
                W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
            }
            let [a, b, c, d, e, f, g, h] = H;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = (S0 + maj) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }
            H[0] = (H[0] + a) >>> 0;
            H[1] = (H[1] + b) >>> 0;
            H[2] = (H[2] + c) >>> 0;
            H[3] = (H[3] + d) >>> 0;
            H[4] = (H[4] + e) >>> 0;
            H[5] = (H[5] + f) >>> 0;
            H[6] = (H[6] + g) >>> 0;
            H[7] = (H[7] + h) >>> 0;
        }
        const result = new Uint8Array(32);
        const rv = new DataView(result.buffer);
        H.forEach((hv, i) => rv.setUint32(i * 4, hv, false));
        return result;
    }

    // SHA-256 implementation (uses crypto.subtle when available, pure JS fallback otherwise)
    async sha256(message: string) {
        // read single char code
        const bytes = new Uint8Array(message.length);
        for (let i = 0; i < message.length; i++) {
            bytes[i] = message.charCodeAt(i);
        }
        const msgBuffer = bytes;

        if (typeof crypto !== "undefined" && crypto.subtle) {
            const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
            return new Uint8Array(hashBuffer);
        }
        return this.sha256Pure(msgBuffer);
    }

    // Count leading zero bits
    countLeadingZeroBits(hash: Uint8Array<ArrayBuffer>) {
        let zeroBits = 0;
        for (let i = 0; i < hash.length; i++) {
            if (hash[i] === 0) {
                zeroBits += 8;
            } else {
                let byte = hash[i];
                while (byte < 128) {
                    zeroBits++;
                    byte <<= 1;
                }
                break;
            }
        }
        return zeroBits;
    }

    // Solve Proof of Work
    async solvePOW(challenge: string, difficulty: number, statusMsg: string) {
        let nonce = 0;
        let lastUpdate = Date.now();
        const startTime = Date.now();

        while (true) {
            const input = challenge + nonce;
            const hash = await this.sha256(input);
            const zeroBits = this.countLeadingZeroBits(hash);

            if (zeroBits >= difficulty) {
                return nonce;
            }

            nonce++;

            // Update progress every 100ms
            const now = Date.now();
            if (now - lastUpdate > 100) {
                lastUpdate = now;
                const elapsed = (now - startTime) / 1000;
                const hashrate = Math.round(nonce / elapsed);
                const sElm = document.getElementById("status");
                const pElm = document.getElementById("progressBar");

                if (sElm && pElm) {
                    sElm.textContent = statusMsg.replace("{nonce}", nonce.toString(10)).replace("{hashrate}", hashrate.toString(10));
                    // Simulate progress (not accurate but gives visual feedback)
                    const progress = Math.min(95, (nonce / 10000) * 100);
                    pElm.style.width = progress + "%";
                }
            }

            // Yield to browser every 1000 iterations
            if (nonce % 1000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    // Gather client information for bot detection
    gatherClientInformation() {
        const info = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            languages: navigator.languages,
            platform: navigator.platform,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: (<any>navigator)?.deviceMemory,
            screenResolution: `${screen.width}x${screen.height}`,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset(),
            plugins: Array.from(navigator.plugins || []).map(p => p.name),
            webdriver: navigator.webdriver,
            headless: navigator.webdriver ||
                /HeadlessChrome/.test(navigator.userAgent) ||
                !(<any>window).chrome && /Chrome/.test(navigator.userAgent),
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            touchSupport: "ontouchstart" in window,
            timestamp: Date.now()
        };
        return JSON.stringify(info);
    }

    private async initialize() {
        const i18n = new I18N();
        const rcElm = document.getElementById("repudiator-challenge");

        if (rcElm) {
            document.title = i18n.translate("pow.title")

            const sElm = document.getElementById("status");
            const pElm = document.getElementById("progressBar");

            try {
                const token = rcElm.innerText;
                const payload: POWPayload = JSON.parse(atob(token));

                const challenge = atob(payload.challenge);
                const difficulty = payload.difficulty;

                console.log("Challenge:", challenge);
                console.log("Difficulty:", difficulty, "bits");

                // Solve the Proof of Work
                sElm && (sElm.textContent = i18n.translate("pow.calculating"));
                const solution = await this.solvePOW(challenge, difficulty, i18n.translate("pow.calculatingProgress"));

                console.log("Solution found:", solution);
                pElm && (pElm.style.width = "100%");
                sElm && (sElm.textContent = i18n.translate("pow.verifying"));

                // Gather client information
                const clientInfo = this.gatherClientInformation();

                // Submit the solution
                const form = document.createElement("form");
                form.method = "POST";
                form.action = payload.powURI || window.location.pathname;

                const fields = {
                    "pow_solution": solution.toString(),
                    "information": clientInfo,
                    "pow_challenge_token": token
                };

                for (const [name, value] of Object.entries(fields)) {
                    const input = document.createElement("input");
                    input.type = "hidden";
                    input.name = name;
                    input.value = value;
                    form.appendChild(input);
                }

                document.body.appendChild(form);
                form.submit();
            } catch (error: any) {
                console.error("Error:", error);
                sElm && (sElm.textContent = i18n.translate("pow.error") + error.message);
            }
        }
    }
}