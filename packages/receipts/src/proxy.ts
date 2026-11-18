/** Which chain paths the verifier's same-origin proxy will forward (GET only). */
export const allowedChainPath = (p: string) => /^\/(qorechain|cosmos)\/[A-Za-z0-9_\-./]*$/.test(p) && !p.includes("..");
export const allowedRpcPath = (p: string) => p === "/status";
