// Node harness: load the challenge exactly like popup.js does, then call check().
// usage: node harness.js <dir-with-main.wasm-and-wasm_exec.js> <input> [--dump prefix]
//   --dump prefix  writes prefix.before.bin / prefix.after.bin (whole Go linear memory)
const fs = require('fs'), path = require('path');
const dir = process.argv[2], input = process.argv[3];
const dump = process.argv.indexOf('--dump') > 0 ? process.argv[process.argv.indexOf('--dump') + 1] : null;
const wasmFile = process.env.WASM || path.join(dir, 'main.wasm');

globalThis.window = globalThis;               // popup.js reads window.check
require(path.resolve(dir, 'wasm_exec.js'));
const go = new Go();

WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then(({ instance }) => {
  go.run(instance);                           // main() registers window.check and blocks
  const mem = () => Buffer.from(instance.exports.mem.buffer.slice(0));
  if (dump) fs.writeFileSync(dump + '.before.bin', mem());
  const res = check(input);
  if (dump) fs.writeFileSync(dump + '.after.bin', mem());
  console.log(res);
  process.exit(0);
});
