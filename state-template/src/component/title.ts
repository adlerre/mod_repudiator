export class TitleComponent {

    private container: HTMLElement | null = null;

    private parent: HTMLElement | null = null;

    private readonly template: HTMLElement | null = null;

    constructor(container: HTMLElement | null = null) {
        this.container = container;
        this.template = this.copyTemplate();
    }

    public setTitle(title: string, parent: HTMLElement | null = null) {
        if (this.template) {
            const elm = <HTMLElement>this.template.cloneNode(true);
            if (elm) {
                elm.innerHTML = title;
                elm.removeAttribute("rep-title");

                const p = parent || this.parent || document.body;
                let ph: HTMLElement | null = null;

                for (const c of p.childNodes) {
                    if (c.nodeType === c.COMMENT_NODE && "rep-title" === c.nodeValue) {
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
        const tmpls = (this.container || document).querySelectorAll("[rep-title]");

        if (tmpls.length > 1) {
            console.warn("Found title templates.");
        }

        const elm = <HTMLElement>tmpls[0].cloneNode(true);
        this.parent = tmpls[0].parentElement;

        const ph = document.createComment("rep-title");
        this.parent?.insertBefore(ph, tmpls[0]);

        tmpls.forEach(t => t.remove());

        return elm;
    }

}