export class I18N {

    private static FN_REGEX: RegExp = /\{\{\s*translate\s*\(\s*[\"']+([^\"']+)[\"']+\s*\)\s\}\}/;

    private readonly defaultLang: string;

    private currentLang: string | null = null;

    private messages = require("../assets/messages.json");

    constructor(defaultLang: string | undefined = undefined) {
        this.defaultLang = defaultLang || "en";
        this.detect();
        this.translateDOM();
    }

    public detect(): void {
        try {
            const locale = new Intl.Locale(navigator.language);
            this.currentLang = locale.language;
        } catch (e) {
            this.currentLang = this.defaultLang;
        }
    }

    public translateDOM() {
        const ms = document.body.innerHTML.matchAll(new RegExp(I18N.FN_REGEX, "g"));
        for (const m of ms) {
            const msg = this.translate(m[1]);
            document.body.innerHTML = document.body.innerHTML.replace(m[0], msg);
        }
    }

    public translate(message: string) {
        return this.findMessage(this.currentLang, message) || this.findMessage(this.defaultLang, message) || message;
    }

    private findMessage(lang: string | null, message: string) {
        if (lang) {
            const msgs = this.messages[lang];
            const mp = message.split(".");

            let c = 0;
            let tmp = msgs;
            for (const m of mp) {
                if (typeof tmp === "object") {
                    tmp = tmp[m];
                    c++;
                }
            }

            if (c === mp.length && typeof tmp === "string") {
                return tmp;
            }
        }

        return null;
    }

}
