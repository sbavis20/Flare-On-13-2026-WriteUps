// Run the hooked wasm and print a call trace with big-integer arguments decoded.
// usage: node trace.js <chal-dir> patched.wasm <input> [filter-regex]
//
// Go/wasm passes arguments on the Go stack: [SP+8], [SP+16], ...
// The obfuscated bigint type is { neg u8 ; pad ; data *byte ; len int ; cap int }
// with little-endian magnitude bytes (recovered from main.WtD0ajazVx55 / main.R3nNAl).
const fs = require('fs'), path = require('path');
const [dir, wasm, input, filt] = process.argv.slice(2);
globalThis.window = globalThis;
require(path.resolve(dir, 'wasm_exec.js'));
const go = new Go();
let inst, on = false;
const NAME = { 3251: 'bigFromInt', 3252: 'bigFromBytes', 3254: 'cmp', 3256: 'inc', 3257: 'dec',
  3258: 'mul', 3261: 'divmod', 3262: 'modpow', 3267: 'parseNode', 3268: 'isPrimitiveRoot',
  3269: 'verifyNode', 3270: 'check' };
function big(dv, p) {
  if (!p || p > dv.byteLength - 32) return 'nil';
  const neg = dv.getUint8(p), mp = Number(dv.getBigUint64(p + 8, true)), l = Number(dv.getBigUint64(p + 16, true));
  if (l > 80) return '?';
  let v = 0n; for (let i = l - 1; i >= 0; i--) v = (v << 8n) | BigInt(dv.getUint8(mp + i));
  return (neg ? '-' : '') + '0x' + v.toString(16);
}
const real = go.importObject.gojs['runtime.nanotime1'];
go.importObject.gojs['runtime.nanotime1'] = (sp) => {
  if ((sp >>> 0) < 0x70000000) return real(sp);
  if (!on) return;
  const f = (sp >>> 0) - 0x70000000, s = inst.exports.getsp() >>> 0, dv = new DataView(inst.exports.mem.buffer);
  const a = i => Number(dv.getBigUint64(s + 8 * i, true));
  let t = NAME[f]; if (!t) return;
  if (f == 3254) t += `(${big(dv, a(1))}, ${big(dv, a(2))})`;
  else if (f == 3262) t += `(${big(dv, a(1))} ^ ${big(dv, a(2))} mod ${big(dv, a(3))})`;
  else if (f == 3268) t += `(${big(dv, a(1))}, p=${big(dv, a(2))}, nfactors=${a(4)})`;
  else if (f == 3258 || f == 3261) t += `(${big(dv, a(1))}, ${big(dv, a(2))})`;
  else if (f == 3256 || f == 3257) t += `(${big(dv, a(1))})`;
  else if (f == 3251) t += `(${a(1)})`;
  else if (f == 3267 || f == 3252) t += `(len=${a(2)})`;
  if (filt && !new RegExp(filt).test(t)) return;
  console.log(t);
};
WebAssembly.instantiate(fs.readFileSync(wasm), go.importObject).then(r => {
  inst = r.instance; go.run(inst); on = true;
  const res = check(input); on = false;
  console.log('=> ' + res); process.exit(0);
});
