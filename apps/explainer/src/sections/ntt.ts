// Section 4: the NTT, drawn as the real butterfly network acting on s[0].
import { Q } from '@autumntrace/latticework/internals';
import { dependencyCone, influenceCone, multiplyCheck, NTT_LAYERS, nttLayers, type Exchange } from '../model.ts';
import { canvas, COLORS, el, figure, fmt, hideTooltip, html, pointer, ringColor, section, showTooltip } from '../ui.ts';

const ROW = 2; // px per coefficient
const BAR = 12; // px per column of coefficients
const TOP = 22;
const LEFT = 8;

export function nttSection(ex: Exchange): HTMLElement {
  const s0 = ex.keygen.s[0]!;
  const layers = nttLayers(s0);
  const check = multiplyCheck(s0, ex.keygen.aHat[0]![0]!, 10);
  const { root, body } = section('ntt', '04', 'The number-theoretic transform');

  body.append(
    html(`<p>Everything in ML-KEM is arithmetic on polynomials mod X<sup>256</sup> + 1, and multiplying two of them the schoolbook way takes
      65,536 coefficient products. The number-theoretic transform is an FFT over Z<sub>q</sub>: after it, multiplication is almost pointwise.</p>
      <p>The "almost" is specific to these parameters. 17 is a 256th root of unity mod 3329 but not a 512th, so X<sup>256</sup> + 1 splits into
      128 quadratic factors rather than 256 linear ones. The NTT therefore has 7 layers instead of 8, and the product in the NTT domain multiplies
      coefficients in pairs, as degree-1 polynomials modulo X<sup>2</sup> − ζ<sup>2·BitRev7(i)+1</sup>.</p>`),
  );

  const width = 760;
  const height = TOP + 256 * ROW + 4;
  const colGap = (width - LEFT * 2 - BAR) / 7;
  const colX = (layer: number) => LEFT + layer * colGap;
  const rowY = (row: number) => TOP + row * ROW + ROW / 2;
  const { canvas: c, ctx } = canvas(width, height, 'The seven butterfly layers of the NTT applied to the first polynomial of s');

  function draw(highlight: Set<number>[] | null, mode: 'in' | 'out' | null) {
    ctx.clearRect(0, 0, width, height);
    ctx.font = '11px ui-monospace, Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.fillStyle = COLORS.muted;
    ctx.fillText('s[0]', colX(0) + BAR / 2, 11);
    for (let l = 1; l <= 7; l++) ctx.fillText(l === 7 ? 'ŝ[0]' : `len ${NTT_LAYERS[l - 1]}`, colX(l) + BAR / 2, 11);

    // Butterfly wires: row j of layer l - 1 feeds rows j and j ^ len of layer l.
    for (let l = 1; l <= 7; l++) {
      const len = NTT_LAYERS[l - 1]!;
      const x0 = colX(l - 1) + BAR;
      const x1 = colX(l);
      for (const lit of [false, true]) {
        if (lit && !highlight) continue;
        ctx.beginPath();
        for (let j = 0; j < 256; j++) {
          for (const from of [j, j ^ len]) {
            const on = highlight
              ? mode === 'out'
                ? highlight[l]!.has(j) && highlight[l - 1]!.has(from)
                : highlight[l - 1]!.has(from) && highlight[l]!.has(j)
              : false;
            if (on !== lit) continue;
            ctx.moveTo(x0, rowY(from));
            ctx.lineTo(x1, rowY(j));
          }
        }
        ctx.strokeStyle = lit ? (mode === 'out' ? COLORS.teal : COLORS.amber) : highlight ? 'rgba(141,150,165,0.05)' : 'rgba(141,150,165,0.16)';
        ctx.lineWidth = lit ? 0.9 : 0.6;
        ctx.stroke();
      }
    }

    // Coefficient columns, coloured by value (cyclic, like Z_q).
    layers.forEach((p, l) => {
      ctx.strokeStyle = COLORS.line;
      ctx.lineWidth = 1;
      ctx.strokeRect(colX(l) - 1.5, TOP - 1.5, BAR + 3, 256 * ROW + 3);
      for (let j = 0; j < 256; j++) {
        const dim = highlight && !highlight[l]!.has(j);
        ctx.globalAlpha = dim ? 0.25 : 1;
        ctx.fillStyle = ringColor(p[j]! / Q);
        ctx.fillRect(colX(l), TOP + j * ROW, BAR, ROW);
      }
    });
    ctx.globalAlpha = 1;
  }
  draw(null, null);

  c.addEventListener('mousemove', (ev) => {
    const { x, y } = pointer(c, ev);
    const row = Math.floor((y - TOP) / ROW);
    if (row < 0 || row > 255) {
      draw(null, null);
      return hideTooltip();
    }
    const mode = x > width / 2 ? 'out' : 'in';
    const cone = mode === 'out' ? dependencyCone(row) : influenceCone(row);
    draw(cone, mode);
    showTooltip(
      ev,
      mode === 'out'
        ? `ŝ[0][${row}] = ${layers[7]![row]}\ndepends on ${cone[0]!.size} of the 256 inputs: every ${row % 2 === 0 ? 'even' : 'odd'} index`
        : `s[0][${row}] = ${layers[0]![row]! > Q / 2 ? layers[0]![row]! - Q : layers[0]![row]}\nreaches ${cone[7]!.size} of the 256 outputs`,
    );
  });
  c.addEventListener('mouseleave', () => {
    draw(null, null);
    hideTooltip();
  });

  body.append(
    figure(
      c,
      el(
        'p',
        { class: 'figure__caption' },
        'The real transform of s[0], one column per layer. Each layer pairs row j with row j XOR len and replaces them with a ± ζ·b. Hover the right half to see which inputs an output depends on, the left half to see where an input goes: always 128 rows, because the eighth layer, the one that would mix even and odd indices, is the one that is missing.',
      ),
    ),
    figure(
      el(
        'p',
        { style: 'margin:0', 'data-testid': 'ntt-check' },
        el('span', { class: `badge ${check.agree ? 'badge--ok' : 'badge--bad'}` }, check.agree ? 'equal' : 'different'),
        ` s[0] · Â[0][0] computed both ways in this tab: schoolbook ${fmt.ms(check.schoolbookMs)}, NTT → base-case products → inverse NTT ${fmt.ms(check.nttMs)}`,
        check.nttMs > 0 ? ` (${(check.schoolbookMs / check.nttMs).toFixed(0)}× faster)` : '',
        `, averaged over ${check.reps} runs. All 256 coefficients ${check.agree ? 'agree' : 'do not agree'}.`,
      ),
    ),
  );
  return root;
}
