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

const fs = require("node:fs");
const path = require("node:path");
const buffer = require("node:buffer");

const args = process.argv.slice(2);

function toHex(data) {
    let u = new Uint8Array(data),
        a = new Array(u.length),
        i = u.length;

    while (i--) {
        a[i] = (u[i] < 16 ? "0" : "") + u[i].toString(16);
    }
    u = null;

    return a;
}

function prettyPrint(data, len, prefix) {
    let res = "";
    const p = prefix || "";

    for (let i = 0; i < data.length; i++) {
        res += i % len === 0 ? i === 0 ? p : "\n" + p : "";
        res += "0x" + data[i] + (i < data.length - 1 ? ", " : "");
    }

    return res;
}

try {
    const inputFile = path.join(process.cwd(), args[0]);
    const outputFile = path.join(process.cwd(), args[1]);
    const prefix = args[2] || path.basename(inputFile).replaceAll(/[.-]/g, "_");

    fs.readFile(inputFile, (err, data) => {
        if (!err) {
            const embedded = `const int ${prefix}_fsize = ${data.length};\nconst unsigned char ${prefix}_file[] = {\n${prettyPrint(toHex(data), 16, "\t")}\n};`;
            fs.writeFileSync(outputFile, embedded, "utf8");
        }
    });
} catch (err) {
    console.error(err);
}