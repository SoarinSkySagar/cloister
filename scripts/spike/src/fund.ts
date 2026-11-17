/**
 * Send test QOR from the operator to another role (hybrid-signed MsgSend).
 *   pnpm spike:fund -- --to watchtower --amount 50          (dry run)
 *   pnpm spike:fund -- --to watchtower --amount 50 --send
 * Testnet only; capped at 100 QOR per call.
 */
import { addressFor, formatQor, testnetClient, txClientFor, QOR, type Role } from "@cloister/common";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const to = flag("--to") as Role | undefined;
const amountQor = Number(flag("--amount"));
const SEND = args.includes("--send");

if (to !== "watchtower" && to !== "relayer") throw new Error("--to must be watchtower or relayer");
if (!Number.isInteger(amountQor) || amountQor <= 0 || amountQor > 100) throw new Error("--amount must be a whole number of QOR, 1..100");

const rdk = testnetClient();
const from = await addressFor("operator");
const recipient = await addressFor(to);
if (!from || !recipient) throw new Error("operator or recipient mnemonic missing in .env");
const amount = BigInt(amountQor) * QOR;

console.log(`send ${formatQor(amount)} from operator ${from}`);
console.log(`  to ${to} ${recipient}`);
if (!SEND) { console.log("dry run: pass --send to broadcast"); process.exit(0); }

const { tx } = await txClientFor(rdk, "operator");
// RdkTxClient has no bank-send helper. Its internal broadcast() adds the
// ML-DSA-87 hybrid extension (the raw backend would send classical-only,
// which the chain refuses).
const client = tx as unknown as { broadcast(msgs: unknown[], opts?: object): Promise<{ code: number; rawLog?: string; transactionHash: string }> };
const msg = {
  typeUrl: "/cosmos.bank.v1beta1.MsgSend",
  value: { fromAddress: from, toAddress: recipient, amount: [{ denom: "uqor", amount: amount.toString() }] },
};
const res = await client.broadcast([msg]);
if (res.code !== 0) throw new Error(`send failed (code ${res.code}): ${res.rawLog ?? ""}`);
console.log(`sent: ${res.transactionHash}`);
console.log(`${to} balance: ${formatQor(await rdk.rest.getBalance(recipient, "uqor"))}`);
