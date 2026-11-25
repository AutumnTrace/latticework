// Section 8: flip a ciphertext bit and watch implicit rejection.
import { bytesEqual, tamper, type Exchange, type TamperResult } from '../model.ts';
import { canvas, COLORS, el, figure, hex, hideTooltip, html, pointer, section, showTooltip } from '../ui.ts';
import { bitGrid } from './exchange.ts';

const COLS = 32;

interface Position {
  field: 'c₁' | 'c₂';
  /** Which polynomial of u (always 0 for v). */
  poly: number;
  coeff: number;
  /** The bit's weight inside its compressed coefficient. */
  significance: number;
  width: number;
}

function locate(ex: Exchange, byte: number, bit: number): Position {
  const { k, du, dv } = ex.kem.params;
  const c1Bytes = 32 * du * k;
  if (byte < c1Bytes) {
    const poly = Math.floor(byte / (32 * du));
    const pos = (byte - poly * 32 * du) * 8 + bit;
    return { field: 'c₁', poly, coeff: Math.floor(pos / du), significance: pos % du, width: du };
  }
  const pos = (byte - c1Bytes) * 8 + bit;
  return { field: 'c₂', poly: 0, coeff: Math.floor(pos / dv), significance: pos % dv, width: dv };
}

export function tamperSection(ex: Exchange): HTMLElement {
  const { params } = ex.kem;
  const c1Bytes = 32 * params.du * params.k;
  const { root, body } = section('tamper', '08', 'Tampering, and implicit rejection');
  body.append(
    html(`<p>Decapsulation never reports failure. After decrypting m′ it re-derives (K′, r′) = G(m′ ‖ H(ek)), runs Bob's encryption again, and
      compares the result with the ciphertext it was given. If they differ anywhere, it returns K̄ = J(z ‖ c) instead of K′: a key that looks
      just as random, but that nobody without z can compute. An attacker who sends modified ciphertexts learns nothing from the answers, because
      there are none, only keys that don't work.</p>
      <p>Click any byte of the ciphertext to flip one of its bits, chosen below. Flipping a low bit of a compressed coefficient often leaves m′
      exactly as it was, since the change is smaller than the noise margin, and the key is rejected anyway: the check is on the ciphertext, not
      on the message.</p>`),
  );

  const rows = Math.ceil(params.ciphertextBytes / COLS);
  const cell = Math.min(13, Math.floor(460 / rows));
  const width = COLS * cell;
  const height = rows * cell;
  const { canvas: grid, ctx } = canvas(width, height, `The ${params.ciphertextBytes} bytes of the ciphertext; click one to flip a bit`);
  grid.dataset['testid'] = 'tamper-grid';
  grid.style.cursor = 'pointer';

  let bit = 0;
  let current: TamperResult | null = null;

  const drawGrid = () => {
    ctx.clearRect(0, 0, width, height);
    for (let i = 0; i < params.ciphertextBytes; i++) {
      const x = (i % COLS) * cell;
      const y = Math.floor(i / COLS) * cell;
      const v = (current?.c ?? ex.c)[i]!;
      const base = i < c1Bytes ? [110, 168, 254] : [242, 184, 75];
      const t = 0.18 + 0.62 * (v / 255);
      ctx.fillStyle = `rgba(${base[0]},${base[1]},${base[2]},${t.toFixed(3)})`;
      ctx.fillRect(x + 0.5, y + 0.5, cell - 1, cell - 1);
      if (current && current.byte === i) {
        ctx.strokeStyle = COLORS.rose;
        ctx.lineWidth = 2;
        ctx.strokeRect(x + 1, y + 1, cell - 2, cell - 2);
      }
    }
  };

  const bitButtons = Array.from({ length: 8 }, (_, b) => {
    const btn = el('button', { type: 'button', class: 'button button--small', 'aria-pressed': String(b === bit), 'data-testid': `tamper-bit-${b}` }, String(b));
    btn.addEventListener('click', () => {
      bit = b;
      bitButtons.forEach((x, j) => x.setAttribute('aria-pressed', String(j === b)));
      if (current) apply(current.byte);
    });
    return btn;
  });

  const byteInput = el('input', {
    type: 'number',
    min: 0,
    max: params.ciphertextBytes - 1,
    value: 0,
    'aria-label': 'Byte index',
    'data-testid': 'tamper-byte',
    style: 'width:84px; padding:4px 6px; background:var(--panel-2); color:var(--text); border:1px solid var(--line); border-radius:6px; font:13px var(--mono)',
  });
  const flipButton = el('button', { type: 'button', class: 'button button--small', 'data-testid': 'tamper-flip' }, 'flip');
  const resetButton = el('button', { type: 'button', class: 'button button--small button--quiet', 'data-testid': 'tamper-reset' }, 'reset');
  const result = el('div', { 'data-testid': 'tamper-result' });

  function renderResult() {
    result.replaceChildren();
    if (!current) {
      result.append(
        el('p', { class: 'verdict verdict--ok', 'data-testid': 'tamper-verdict' }, 'Untouched: c′ = c, so Alice keeps K′'),
        el(
          'div',
          { class: 'result-grid' },
          el('span', { class: 'label' }, 'm′'),
          el('span', {}, 'equals m in all 256 bits'),
          el('span', { class: 'label' }, 'Alice'),
          el('span', { class: 'hex' }, hex(ex.aliceKey)),
          el('span', { class: 'label' }, 'Bob'),
          el('span', { class: 'hex' }, hex(ex.bobKey)),
        ),
      );
      return;
    }
    const r = current;
    const pos = locate(ex, r.byte, r.bit);
    const accepted = r.trace.accepted;
    result.append(
      el(
        'p',
        { class: `verdict ${accepted ? 'verdict--ok' : 'verdict--bad'}`, 'data-testid': 'tamper-verdict' },
        accepted ? 'Accepted (this should not happen)' : 'Rejected: Alice now holds K̄ = J(z ‖ c)',
      ),
      el(
        'div',
        { class: 'result-grid' },
        el('span', { class: 'label' }, 'flipped'),
        el(
          'span',
          {},
          `byte ${r.byte}, bit ${r.bit}: bit ${pos.significance} of ${pos.width} in coefficient ${pos.coeff} of ${pos.field === 'c₁' ? `u[${pos.poly}]` : 'v'} (${pos.field})`,
        ),
        el('span', { class: 'label' }, 'm′'),
        el(
          'span',
          { 'data-testid': 'tamper-message' },
          r.messageBitsChanged === 0
            ? 'identical to m: decryption shrugged the change off'
            : `differs from m in ${r.messageBitsChanged} bit${r.messageBitsChanged === 1 ? '' : 's'}`,
        ),
        el('span', { class: 'label' }, 'c′'),
        el('span', {}, `re-encrypting m′ differs from the received c in ${r.ciphertextBytesDiffer} of ${params.ciphertextBytes} bytes`),
        el('span', { class: 'label' }, 'K′'),
        el('span', { class: 'hex hex--dim' }, hex(r.trace.kPrime)),
        el('span', { class: 'label' }, 'K̄'),
        el('span', { class: 'hex', style: `color:${COLORS.rose}` }, hex(r.trace.kBar)),
        el('span', { class: 'label' }, 'Alice'),
        el('span', { class: 'hex' }, hex(r.key)),
        el('span', { class: 'label' }, 'Bob'),
        el('span', { class: 'hex' }, hex(ex.bobKey)),
      ),
      el(
        'div',
        { style: 'margin-top:14px' },
        el('h3', {}, 'm′, with bits that differ from m outlined'),
        bitGrid(r.trace.mPrime, 'The decrypted message bits', ex.m),
      ),
      el(
        'p',
        { class: 'figure__caption' },
        el(
          'span',
          { class: `badge ${bytesEqual(r.key, ex.bobKey) ? 'badge--ok' : 'badge--bad'}` },
          bytesEqual(r.key, ex.bobKey) ? 'keys match' : 'keys differ',
        ),
        ' Bob never finds out from Alice directly; their next encrypted message simply fails to decrypt.',
      ),
    );
  }

  function apply(byte: number) {
    current = tamper(ex, byte, bit);
    byteInput.value = String(byte);
    drawGrid();
    renderResult();
  }

  grid.addEventListener('click', (ev) => {
    const { x, y } = pointer(grid, ev);
    const i = Math.floor(y / cell) * COLS + Math.floor(x / cell);
    if (i >= 0 && i < params.ciphertextBytes) apply(i);
  });
  grid.addEventListener('mousemove', (ev) => {
    const { x, y } = pointer(grid, ev);
    const i = Math.floor(y / cell) * COLS + Math.floor(x / cell);
    if (i < 0 || i >= params.ciphertextBytes) return hideTooltip();
    const p = locate(ex, i, bit);
    showTooltip(
      ev,
      `byte ${i} = 0x${ex.c[i]!.toString(16).padStart(2, '0')} (${p.field})\nbit ${bit} is bit ${p.significance} of coefficient ${p.coeff} of ${p.field === 'c₁' ? `u[${p.poly}]` : 'v'}`,
    );
  });
  grid.addEventListener('mouseleave', hideTooltip);
  flipButton.addEventListener('click', () => {
    const i = Math.min(Math.max(Number.parseInt(byteInput.value, 10) || 0, 0), params.ciphertextBytes - 1);
    apply(i);
  });
  resetButton.addEventListener('click', () => {
    current = null;
    drawGrid();
    renderResult();
  });

  drawGrid();
  renderResult();

  body.append(
    figure(
      el(
        'div',
        { class: 'figure__row' },
        el(
          'div',
          {},
          el('h3', {}, `c, ${params.ciphertextBytes} bytes: c₁ blue, c₂ amber`),
          grid,
          el(
            'div',
            { style: 'margin-top:12px; display:flex; flex-wrap:wrap; gap:8px; align-items:center; font:12px var(--mono); color:var(--muted)' },
            'bit',
            el('span', { class: 'bit-picker' }, ...bitButtons),
          ),
          el(
            'div',
            { style: 'margin-top:8px; display:flex; gap:8px; align-items:center; font:12px var(--mono); color:var(--muted)' },
            'byte',
            byteInput,
            flipButton,
            resetButton,
          ),
        ),
        el('div', { style: 'flex:1; min-width:320px' }, result),
      ),
    ),
  );
  return root;
}
