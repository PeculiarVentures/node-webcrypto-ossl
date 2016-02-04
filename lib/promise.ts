interface PromiseFunc {
    (resolve: Function, reject: Function): void;
}

declare class Promise {
    constructor(func: PromiseFunc);

    then(): Promise;
    catch(): Promise;
} 