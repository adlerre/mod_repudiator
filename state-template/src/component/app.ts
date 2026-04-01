import { TitleComponent } from "./title";
import { ReasonComponent, ReasonType } from "./reason";
import { I18N } from "./i18n";

export interface ReputationState {
    state: string | ReasonType;
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

    private typeFn(rep: number, warn: number, block: number) {
        const neg = block < warn;
        return neg ?
            (rep <= block ? ReasonType.BLOCK :
                rep <= warn ? ReasonType.WARN : null) :
            (rep >= block ? ReasonType.BLOCK
                : rep >= warn ? ReasonType.WARN : null);
    }

    private initialize() {
        const i18n = new I18N();
        const tCmp = new TitleComponent();
        const rCmp = new ReasonComponent();
        const rsElm = document.getElementById("repudiator-state");

        if (rsElm) {
            try {
                const repState: ReputationState = JSON.parse(rsElm.innerText);

                const title = i18n.translate("title." + repState.state);
                document.title = title
                tCmp.setTitle(title);

                if (this.cmpFn(repState.ip, repState.warn, repState.block) || this.cmpFn(repState.perIp, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.ip.headline"),
                        i18n.translate("reason.ip.description"),
                        this.typeFn(repState.ip + repState.perIp, repState.warn, repState.block),
                        repState.ip + repState.perIp
                    );
                }
                if (this.cmpFn(repState.asn, repState.warn, repState.block) || this.cmpFn(repState.perASN, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.asn.headline"),
                        i18n.translate("reason.asn.description"),
                        this.typeFn(repState.asn + repState.perASN, repState.warn, repState.block),
                        repState.asn + repState.perASN
                    );
                }
                if (this.cmpFn(repState.perNet, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.net.headline"),
                        i18n.translate("reason.net.description"),
                        this.typeFn(repState.perNet, repState.warn, repState.block),
                        repState.perNet
                    );
                }
                if (this.cmpFn(repState.ua, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.ua.headline"),
                        i18n.translate("reason.ua.description"),
                        this.typeFn(repState.ua, repState.warn, repState.block),
                        repState.ua
                    );
                }
                if (this.cmpFn(repState.uri, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.uri.headline"),
                        i18n.translate("reason.uri.description"),
                        this.typeFn(repState.uri, repState.warn, repState.block),
                        repState.uri
                    );
                }
                if (this.cmpFn(repState.country, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.country.headline"),
                        i18n.translate("reason.country.description"),
                        this.typeFn(repState.country, repState.warn, repState.block),
                        repState.country
                    );
                }
                if (this.cmpFn(repState.status, repState.warn, repState.block)) {
                    rCmp.addReason(
                        i18n.translate("reason.status.headline"),
                        i18n.translate("reason.status.description"),
                        this.typeFn(repState.status, repState.warn, repState.block),
                        repState.status
                    );
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