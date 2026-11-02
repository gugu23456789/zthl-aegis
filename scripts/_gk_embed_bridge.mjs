// _gk_embed_bridge.mjs — 本地嵌入桥（finding `ECC-FAF2A8F0A0DF` ③-A producer 的 Node 端）。
//
// 复用 gitnexus 自带的 transformers.js 运行时（无新依赖）；默认模型 = 中文 bge-small-zh。
// 用法： node <bridge.mjs> <payload.json> <out.json>
//   payload: { model, txFq, cacheDir?, pooling?, device?, dtype?, maxLength?,
//              batches?:[[i,...],...], texts:[...] }
//   out:     { dim, vectors:[[...], ...] }   （顺序与 payload.texts 一一对应）
//
// 分批由 **上游 Python 预检门**（`gk_finding_embed.preflight_batches`）决定并放入 `batches`
// （每批 = `texts` 的下标数组，保序、无重复、全覆盖）；本桥只按批执行，杜绝全量一次过导致
// ONNX 注意力张量 OOM（552 条一次过实测 ~4.6GB ⟹ 拖崩宿主）。`truncation/max_length` 兜底
// 单条超长文本。
//
// 只读输入、只写 out.json；不触网（模型须已在 cacheDir 中；缺失则 transformers.js 会尝试下载）。
import fs from 'node:fs';

const payloadPath = process.argv[2];
const outPath = process.argv[3];
if (!payloadPath || !outPath) {
  console.error('usage: node _gk_embed_bridge.mjs <payload.json> <out.json>');
  process.exit(2);
}
const p = JSON.parse(fs.readFileSync(payloadPath, 'utf8'));
const { pipeline, env } = await import(p.txFq);
if (p.cacheDir) env.cacheDir = p.cacheDir;
env.allowLocalModels = false;

const extractor = await pipeline('feature-extraction', p.model, {
  device: p.device || 'cpu',
  dtype: p.dtype || 'fp32',
});

const texts = p.texts || [];
const opts = { pooling: p.pooling || 'cls', normalize: true };
if (p.maxLength) {
  opts.truncation = true;      // 兜底单条超长（防单样本炸峰值）
  opts.max_length = p.maxLength;
}

// 分批由上游 Python 预检门（gk_finding_embed.preflight_batches）决定并放入 p.batches
// （每批 = texts 下标数组，保序/无重复/全覆盖）；此处只按批执行，避免全量一次性 OOM。
let dim = 0;
const vectors = new Array(texts.length);
const runBatch = async (idxs) => {
  const chunk = idxs.map((i) => texts[i]);
  const out = await extractor(chunk, opts);
  dim = out.dims[out.dims.length - 1];
  const flat = out.data;
  for (let i = 0; i < idxs.length; i++) {
    vectors[idxs[i]] = Array.from(flat.slice(i * dim, (i + 1) * dim));
  }
};

let batches = Array.isArray(p.batches) ? p.batches : null;
if (!batches) {   // 退化路径：桥独立可用时按 batchSize 顺切
  const B = p.batchSize || 32;
  batches = [];
  for (let s = 0; s < texts.length; s += B) {
    batches.push(Array.from({ length: Math.min(B, texts.length - s) }, (_, k) => s + k));
  }
}
for (const b of batches) await runBatch(b);

fs.writeFileSync(outPath, JSON.stringify({ dim, vectors }));
console.error(`[gk-embed-bridge] model=${p.model} n=${texts.length} dim=${dim} batches=${batches.length}`);
