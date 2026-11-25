// Sections 5 to 7: the public key, encapsulation, and why decapsulation works.
import { Q } from '@autumntrace/latticework/internals';
import { compressionErrors, FAILURE_LOG2, noiseBreakdown, type Exchange } from '../model.ts';
import { tileGrid } from '../tiles.ts';
import { canvas, COLORS, el, figure, fmt, hex, hideTooltip, histogram, html, layoutBar, pointer, ringColor, section, showTooltip } from '../ui.ts';

export function publicKey(ex: Exchange): HTMLElement {
  const { k } = ex.kem.params;
  const { root, body } = section('public-key', '05', 'The key pair');
  body.append(
    html(`<p>With ŝ and ê transformed, the public vector is t̂ = Â ∘ ŝ + ê: ${k * k} products in the NTT domain and ${k} additions. It looks
      exactly as uniform as Â does, which is the claim the whole scheme rests on. The encapsulation key is t̂ packed at 12 bits per coefficient,
      followed by ρ. The decapsulation key is ŝ, then a full copy of the encapsulation key, its hash H(ek), and z: everything decapsulation will
      need, so it never has to recompute anything from the seed.</p>`),
    figure(
      el('h3', {}, 't̂ = Â ∘ ŝ + ê'),
      tileGrid({
        rows: [ex.keygen.tHat],
        color: (v) => ringColor(v / Q),
        describe: (_i, j, idx, v) => `t̂[${j}] coefficient ${idx} = ${v}`,
        cell: 7,
        gap: 12,
        label: 'The public vector t-hat as heatmaps',
        colLabels: Array.from({ length: k }, (_, j) => `t̂[${j}]`),
      }),
      layoutBar('ek', [
        { label: 't̂', bytes: 384 * k, color: COLORS.blue },
        { label: 'ρ', bytes: 32, color: COLORS.violet },
      ]),
      layoutBar('dk', [
        { label: 'ŝ', bytes: 384 * k, color: COLORS.rose },
        { label: 'ek', bytes: 384 * k + 32, color: COLORS.blue },
        { label: 'H(ek)', bytes: 32, color: COLORS.amber },
        { label: 'z', bytes: 32, color: COLORS.teal },
      ]),
    ),
  );
  return root;
}

/** The 256 message bits as a 16 x 16 grid; `changed` outlines bits that differ from `ref`. */
export function bitGrid(bytes: Uint8Array, label: string, ref?: Uint8Array): HTMLCanvasElement {
  const cell = 11;
  const { canvas: c, ctx } = canvas(16 * cell, 16 * cell, label);
  for (let i = 0; i < 256; i++) {
    const bit = (bytes[i >> 3]! >> (i & 7)) & 1;
    const x = (i & 15) * cell;
    const y = (i >> 4) * cell;
    ctx.fillStyle = bit ? COLORS.amber : COLORS.panel2;
    ctx.fillRect(x + 1, y + 1, cell - 2, cell - 2);
    if (ref && bit !== ((ref[i >> 3]! >> (i & 7)) & 1)) {
      ctx.strokeStyle = COLORS.rose;
      ctx.lineWidth = 2;
      ctx.strokeRect(x + 1, y + 1, cell - 2, cell - 2);
    }
  }
  return c;
}

function errorHistogram(errors: number[], bound: number, title: string): SVGSVGElement {
  // Bin into at most ~41 bins across [-bound, bound].
  const width = Math.max(1, Math.ceil((2 * bound + 1) / 41));
  const bins = new Map<number, number>();
  for (const e of errors) {
    const b = Math.floor((e + bound) / width);
    bins.set(b, (bins.get(b) ?? 0) + 1);
  }
  const n = Math.ceil((2 * bound + 1) / width);
  const bars = Array.from({ length: n }, (_, b) => ({ x: b, count: bins.get(b) ?? 0, color: COLORS.violet }));
  return histogram(bars, {
    width: 300,
    height: 150,
    xLabel: (b) => fmt.signed(b * width - bound),
    labelEvery: Math.ceil(n / 4),
    title,
  });
}

export function encapsulation(ex: Exchange): HTMLElement {
  const { k, du, dv, ciphertextBytes } = ex.kem.params;
  const { encrypt } = ex.encaps;
  const uErr = compressionErrors(encrypt.u, du);
  const vErr = compressionErrors([encrypt.v], dv);
  const raw = (k + 1) * 384;
  const { root, body } = section('encapsulation', '06', 'Encapsulation');
  body.append(
    html(`<p>Bob picks a random 32-byte message <code>m</code>. Hashing it together with H(ek) gives both the shared secret K and the randomness
      r for encryption: everything that follows is a deterministic function of m and the public key, which is what will let Alice check Bob's work.</p>
      <p>Fresh noise y, e₁, e₂ comes out of r the same way s and e came out of σ. Then u = Âᵀy + e₁ and v = t̂ᵀy + e₂ + μ, where μ is the message with
      each bit turned into a coefficient of 0 or 1665 ≈ q/2. Finally both are compressed: u to ${du} bits per coefficient, v to only ${dv}. That rounding
      throws information away (up to ±${uErr.bound} and ±${vErr.bound}), and it is why the ciphertext is ${fmt.int(ciphertextBytes)} bytes rather than
      ${fmt.int(raw)}.</p>`),
    figure(
      el(
        'div',
        { class: 'figure__row' },
        el('div', {}, el('h3', {}, 'm, 256 bits'), bitGrid(ex.m, 'The 256 bits of the message m')),
        el(
          'div',
          {},
          el('h3', {}, `rounding error in u (${du} bits), max ±${uErr.maxAbs}`),
          errorHistogram(uErr.errors, uErr.bound, 'Histogram of the rounding error of u'),
        ),
        el(
          'div',
          {},
          el('h3', {}, `rounding error in v (${dv} bits), max ±${vErr.maxAbs}`),
          errorHistogram(vErr.errors, vErr.bound, 'Histogram of the rounding error of v'),
        ),
      ),
      el(
        'dl',
        { class: 'kv', style: 'margin-top:18px' },
        el('dt', {}, 'H(ek)'),
        el('dd', { class: 'hex' }, hex(ex.encaps.hEk)),
        el('dt', {}, 'K'),
        el('dd', { class: 'hex', style: `color:${COLORS.teal}` }, hex(ex.bobKey)),
        el('dt', {}, 'r'),
        el('dd', { class: 'hex' }, hex(ex.encaps.r)),
      ),
      layoutBar('c', [
        { label: `c₁: u at ${du} bits`, bytes: 32 * du * k, color: COLORS.blue },
        { label: `c₂: v at ${dv} bits`, bytes: 32 * dv, color: COLORS.amber },
      ]),
    ),
  );
  return root;
}

/** Angle of a value of Z_q on the ring, 0 at the top, increasing clockwise. */
const angle = (v: number) => (v / Q) * 2 * Math.PI - Math.PI / 2;

export function decapsulation(ex: Exchange): HTMLElement {
  const b = noiseBreakdown(ex);
  const { w, mu } = { w: ex.decaps.decrypt.w, mu: ex.encaps.encrypt.mu };
  const { root, body } = section('decapsulation', '07', 'Why decapsulation works');
  const margin = b.threshold - b.maxAbs;
  body.append(
    html(`<p>Alice computes w = v′ − ŝᵀu′ from the ciphertext and her secret. Expand it and every term with A in it cancels, leaving the message
      plus a sum of small things:</p>
      <p style="font:16px var(--mono); text-align:center; max-width:720px">w = μ + eᵀy − sᵀe₁ + e₂ + Δv − sᵀΔu</p>
      <p>where Δu and Δv are the rounding errors from compression. Each coefficient of w is then rounded to whichever of 0 and q/2 is nearer. That
      gives the right bit as long as the noise stays below q/4 ≈ ${b.threshold}. In this run the largest noise coefficient was ${b.maxAbs}, a margin of
      ${margin}. FIPS 203 puts the chance that any of the 256 coefficients crosses the line at 2<sup>${FAILURE_LOG2[ex.set]}</sup> per exchange for
      ${ex.kem.params.name}.</p>`),
  );

  // The ring: each coefficient of w at its angle on Z_q.
  const size = 360;
  const cw = 420;
  const cx = cw / 2;
  const cy = size / 2;
  const R = 136;
  const { canvas: c, ctx } = canvas(cw, size, 'The 256 coefficients of w placed around a circle representing Z_q');
  const points: { x: number; y: number; i: number }[] = [];
  const drawRing = () => {
    ctx.clearRect(0, 0, cw, size);
    // Decision regions: within q/4 of 0 decodes to 0, within q/4 of q/2 to 1.
    const arc = (from: number, to: number, color: string) => {
      ctx.beginPath();
      ctx.arc(cx, cy, R, angle(from), angle(to));
      ctx.strokeStyle = color;
      ctx.lineWidth = 46;
      ctx.stroke();
    };
    arc(-Q / 4, Q / 4, 'rgba(90,209,179,0.10)');
    arc(Q / 4, (3 * Q) / 4, 'rgba(242,184,75,0.10)');
    ctx.font = '11px ui-monospace, Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = COLORS.muted;
    ctx.fillText('0', cx, cy - R - 30);
    ctx.fillText('q/2', cx, cy + R + 38);
    ctx.fillText('q/4', cx + R + 34, cy + 4);
    ctx.fillText('3q/4', cx - R - 34, cy + 4);
    ctx.fillStyle = COLORS.teal;
    ctx.fillText('decodes to 0', cx, cy - 30);
    ctx.fillStyle = COLORS.amber;
    ctx.fillText('decodes to 1', cx, cy + 40);
    for (const v of [Q / 4, (3 * Q) / 4]) {
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(angle(v)) * (R - 30), cy + Math.sin(angle(v)) * (R - 30));
      ctx.lineTo(cx + Math.cos(angle(v)) * (R + 30), cy + Math.sin(angle(v)) * (R + 30));
      ctx.strokeStyle = COLORS.faint;
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }
    points.length = 0;
    for (let i = 0; i < 256; i++) {
      const bit = mu[i]! !== 0;
      const r = R - 18 + (i % 9) * 4.5;
      const x = cx + Math.cos(angle(w[i]!)) * r;
      const y = cy + Math.sin(angle(w[i]!)) * r;
      points.push({ x, y, i });
      ctx.beginPath();
      ctx.arc(x, y, 2.4, 0, 2 * Math.PI);
      ctx.fillStyle = bit ? COLORS.amber : COLORS.teal;
      ctx.fill();
    }
  };
  drawRing();
  c.addEventListener('mousemove', (ev) => {
    const p = pointer(c, ev);
    let best: { i: number; d: number } | null = null;
    for (const pt of points) {
      const d = Math.hypot(pt.x - p.x, pt.y - p.y);
      if (d < 7 && (!best || d < best.d)) best = { i: pt.i, d };
    }
    if (!best) return hideTooltip();
    const i = best.i;
    const bit = mu[i]! !== 0 ? 1 : 0;
    showTooltip(ev, `w[${i}] = ${w[i]}\nmessage bit ${bit}, noise ${fmt.signed(b.noise[i]!)}`);
  });
  c.addEventListener('mouseleave', hideTooltip);

  // Noise histogram against ±q/4.
  const binW = 16;
  const lo = -Math.ceil(b.threshold / binW);
  const counts = new Map<number, number>();
  for (const n of b.noise) {
    const k = Math.floor(n / binW);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const bars = Array.from({ length: -2 * lo }, (_, j) => ({ x: lo + j, count: counts.get(lo + j) ?? 0, color: COLORS.blue }));
  const hist = histogram(bars, {
    width: 440,
    height: 180,
    xLabel: (x) => fmt.signed(x * binW),
    labelEvery: 13,
    markers: [
      { x: lo, label: `−q/4`, color: COLORS.rose },
      { x: -lo - 1, label: `+q/4`, color: COLORS.rose },
    ],
    title: 'Histogram of the decryption noise against the q/4 threshold',
  });

  const table = el(
    'table',
    { class: 'terms' },
    el('thead', {}, el('tr', {}, el('th', {}, 'term'), el('th', {}, 'std dev'), el('th', {}, 'max |·|'))),
    el(
      'tbody',
      {},
      ...b.terms.map((t) => el('tr', {}, el('td', {}, t.label), el('td', {}, t.std.toFixed(1)), el('td', {}, String(t.maxAbs)))),
      el('tr', { class: 'total' }, el('td', {}, 'w − μ'), el('td', {}, stdOf(b.noise).toFixed(1)), el('td', { 'data-testid': 'noise-max' }, String(b.maxAbs))),
    ),
  );

  body.append(
    figure(
      el(
        'div',
        { class: 'figure__row' },
        c,
        el(
          'div',
          { style: 'flex:1; min-width:300px' },
          el('h3', {}, `noise w − μ, all 256 coefficients, bins of ${binW}`),
          hist,
          el('h3', { style: 'margin-top:18px' }, 'where it comes from'),
          table,
          el(
            'p',
            { class: 'figure__caption' },
            el('span', { class: `badge ${b.termsMatch ? 'badge--ok' : 'badge--bad'}` }, b.termsMatch ? 'exact' : 'mismatch'),
            ` The five terms, recomputed from the traced s, e, y, e₁, e₂ and rounding errors, add up to the w that decryption produced on ${b.termsMatch ? 'all 256' : 'not all'} coefficients. ${b.wrongBits === 0 ? 'Every message bit decoded correctly.' : `${b.wrongBits} message bits decoded wrongly.`}`,
          ),
        ),
      ),
      el(
        'p',
        { class: 'figure__caption' },
        'Left: the 256 coefficients of w around Z_q, teal where the message bit was 0 and amber where it was 1. They cluster at 0 and q/2, nowhere near the dashed boundaries at q/4 and 3q/4. Hover a dot for its value.',
      ),
    ),
  );
  return root;
}

function stdOf(xs: number[]): number {
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  return Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length);
}
