/*
 * This program is free software; you can use it, redistribute it
 * and / or modify it under the terms of the GNU General Public License
 * (GPL) as published by the Free Software Foundation; either version 3
 * of the License or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program, in a file called gpl.txt or license.txt.
 * If not, write to the Free Software Foundation Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307 USA
 */

export interface Reason {
    headline: string;
    description: string;
}

export class ReasonComponent {

    public reasons: Array<Reason> = [];

    private container: HTMLElement | null = null;

    private parent: HTMLElement | null = null;

    private readonly template: HTMLElement | null = null;

    constructor(container: HTMLElement | null = null) {
        this.container = container;
        this.template = this.copyTemplate();
    }

    public addReason(headline: string, description: string) {
        this.reasons.push({headline, description});
    }

    public outputReasons(parent: HTMLElement | null = null) {
        for (const reason of this.reasons) {
            const elm = this.buildReason(reason);

            if (elm) {
                const p = parent || this.parent || document.body;
                let ph: HTMLElement | null = null;

                for (const c of p.childNodes) {
                    if (c.nodeType === c.COMMENT_NODE && "rep-reason-tmpl" === c.nodeValue) {
                        ph = <HTMLElement>c;
                        break;
                    }
                }

                if (ph) {
                    p.insertBefore(elm, ph.nextSibling);
                }
            }
        }
    }

    private copyTemplate() {
        const reasonTmpls = (this.container || document).querySelectorAll("[rep-reason-tmpl]");

        if (reasonTmpls.length > 1) {
            console.warn("Found multiple reason templates.");
        }

        const elm = <HTMLElement>reasonTmpls[0].cloneNode(true);
        this.parent = reasonTmpls[0].parentElement;

        const ph = document.createComment("rep-reason-tmpl");
        this.parent?.insertBefore(ph, reasonTmpls[0]);

        reasonTmpls.forEach(t => t.remove());

        return elm;
    }

    private buildReason(reason: Reason) {
        if (!this.template) {
            return null;
        }

        const reasonElm = <HTMLElement>this.template.cloneNode(true);
        reasonElm.removeAttribute("rep-reason-tmpl");

        const rh = reasonElm.querySelector("[rep-reason-headline]");
        const rb = reasonElm.querySelector("[rep-reason-body]");
        if (rh && rb) {
            rh.innerHTML = reason.headline;
            rb.innerHTML = reason.description;

            rh.removeAttribute("rep-reason-headline");
            rb.removeAttribute("rep-reason-body");
        }

        return reasonElm;
    }

}