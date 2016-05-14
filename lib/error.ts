export const ERROR_WRONG_ALGORITHM = "Unsupported algorithm in use '%1'";
export const ERROR_NOT_SUPPORTED_METHOD = "Method is not supported";


function printf(text: string, ...args: any[]) {
    let msg: string = text;
    let regFind = /[^%](%\d+)/g;
    let match: RegExpExecArray = null;
    let matches: { arg: string, index: number }[] = [];
    while (match = regFind.exec(msg)) {
        matches.push({ arg: match[1], index: match.index });
    }

    // replace matches
    for (let i = matches.length - 1; i >= 0; i--) {
        let item = matches[i];
        let arg = item.arg.substring(1);
        let index = item.index + 1;
        msg = msg.substring(0, index) + arguments[+arg] + msg.substring(index + 1 + arg.length);
    }

    // convert %% -> %
    msg = msg.replace("%%", "%");

    return msg;
}

export class WebCryptoError extends Error {
    constructor(template: string, ...args: any[]) {
        super();
        this.message = printf.apply(this, arguments);

        this.stack = (new Error(this.message)).stack;
    }
}

export class AlgorithmError extends WebCryptoError {}

export class CryptoKeyError extends WebCryptoError {}