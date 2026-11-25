// Sections 1 to 3: the seeds, the matrix A-hat, and the small noise.
import { centered, Q } from '@autumntrace/latticework/internals';
import { cbdHistogram, sampleCandidates, type Exchange } from '../model.ts';
import { tileGrid } from '../tiles.ts';
import { COLORS, diverging, el, figure, fmt, hex, histogram, html, ringColor, section } from '../ui.ts';

export function seeds(ex: Exchange): HTMLElement {
  const { k } = ex.kem.params;
  const { root, body } = section('seeds', '01', 'Two seeds');
  body.append(
    html(`<p>Key generation starts from two 32-byte random seeds. <code>d</code> determines the whole key pair. <code>z</code> is only stored, for
      the rejection key at the very end. G = SHA3-512 turns <code>d</code>, plus one byte <code>k = ${k}</code> that keeps the three parameter sets
      apart, into two halves: <code>ρ</code>, which is public and expands into the matrix, and <code>σ</code>, which is secret and expands into the noise.</p>`),
    figure(
      el(
        'dl',
        { class: 'kv' },
        el('dt', {}, 'd'),
        el('dd', { class: 'hex' }, hex(ex.d)),
        el('dt', {}, 'z'),
        el('dd', { class: 'hex' }, hex(ex.z)),
        el('dt', {}, `G(d ‖ ${k})`),
        el('dd', { class: 'hex hex--dim' }, '64 bytes, split in two:'),
        el('dt', {}, 'ρ'),
        el('dd', { class: 'hex', style: `color: ${COLORS.blue}` }, hex(ex.keygen.rho)),
        el('dt', {}, 'σ'),
        el('dd', { class: 'hex', style: `color: ${COLORS.rose}` }, hex(ex.keygen.sigma)),
      ),
    ),
  );
  return root;
}

export function matrix(ex: Exchange): HTMLElement {
  const { k } = ex.kem.params;
  const { sampling } = ex.keygen;
  const { root, body } = section('matrix', '02', 'The matrix Â, expanded from ρ');
  const rejectRate = sampling.rejected / sampling.candidates;
  body.append(
    html(`<p>Â is a ${k} × ${k} matrix of polynomials, each with 256 coefficients mod q = 3329. Nobody chooses it: entry (i, j) is
      SHAKE128(ρ ‖ j ‖ i) read 12 bits at a time, keeping the values below 3329. 4096 − 3329 = 767 of every 4096 candidates are thrown away,
      18.7% on average. This run drew ${fmt.int(sampling.candidates)} candidates for its ${k * k} polynomials and threw away
      ${fmt.int(sampling.rejected)} (${fmt.pct(rejectRate)}).</p>
      <p>Since anyone can regenerate Â from 32 bytes, it never travels: the public key carries ρ instead of ${fmt.int(k * k * 384)} bytes of matrix.
      It is sampled directly in the NTT domain (that is what the hat means), so the implementation never has to transform it.</p>`),
    figure(
      el(
        'div',
        { class: 'figure__row' },
        tileGrid({
          rows: ex.keygen.aHat,
          color: (v) => ringColor(v / Q),
          describe: (i, j, idx, v) => `Â[${i}][${j}] = SampleNTT(ρ ‖ ${j} ‖ ${i})\ncoefficient ${idx} = ${v}`,
          cell: k === 4 ? 6 : 7,
          gap: 12,
          label: `The ${k} by ${k} matrix A-hat as heatmaps of its coefficients`,
          colLabels: Array.from({ length: k }, (_, j) => `j = ${j}`),
          rowLabels: Array.from({ length: k }, (_, i) => `i = ${i}`),
        }),
        candidatesPanel(ex),
      ),
      el(
        'p',
        { class: 'figure__caption' },
        'Each tile is one polynomial, its 256 coefficients in rows of 16. Colours wrap around the way Z_q does: 0 is dark, q/4 blue, q/2 pale, 3q/4 amber, and back to dark at q − 1. Uniform noise, by construction. Hover for values.',
      ),
    ),
  );
  return root;
}

function candidatesPanel(ex: Exchange): HTMLElement {
  const candidates = sampleCandidates(ex.keygen.rho, 0, 0, 48);
  const accepted = candidates.filter((c) => c.accepted).map((c) => c.value);
  const matches = accepted.every((v, i) => ex.keygen.aHat[0]![0]![i] === v);
  return el(
    'div',
    { style: 'max-width:340px' },
    el('h3', {}, 'the first 48 candidates for Â[0][0]'),
    el(
      'div',
      { class: 'candidates', 'data-testid': 'candidates' },
      ...candidates.map((c) =>
        el('span', { class: c.accepted ? '' : 'rejected', title: c.accepted ? 'below 3329: kept' : '3329 or more: thrown away' }, String(c.value)),
      ),
    ),
    el(
      'p',
      { class: 'figure__caption' },
      el('span', { class: `badge ${matches ? 'badge--ok' : 'badge--bad'}` }, matches ? 'same' : 'different'),
      ` Read straight from SHAKE128(ρ ‖ 0 ‖ 0), 3 bytes per pair. The ${accepted.length} kept here are the first ${accepted.length} coefficients of Â[0][0] above.`,
    ),
  );
}

export function noise(ex: Exchange): HTMLElement {
  const { k, eta1 } = ex.kem.params;
  const { s, e } = ex.keygen;
  const { root, body } = section('noise', '03', 'Small noise: the secret s and the error e');
  const probs = eta1 === 2 ? '1/16, 4/16, 6/16, 4/16 and 1/16' : '1/64, 6/64, 15/64, 20/64, 15/64, 6/64 and 1/64';
  const bins = cbdHistogram([...s, ...e], eta1);
  body.append(
    html(`<p>The secret <code>s</code> and the error <code>e</code> are vectors of ${k} small polynomials, expanded from σ with SHAKE256.
      Each coefficient is the difference of two sums of η = ${eta1} coin flips, so it lies between −${eta1} and ${eta1} with probabilities
      ${probs}: a centred binomial distribution, which is cheap to sample without branching.</p>
      <p>Small is the whole point. The public key will be t = A·s + e. Without <code>e</code> that is a linear system and <code>s</code> falls out of
      Gaussian elimination; with it, finding <code>s</code> is the Module Learning With Errors problem, which nobody knows how to solve efficiently,
      on a quantum computer or otherwise.</p>`),
    figure(
      el(
        'div',
        { class: 'figure__row' },
        el(
          'div',
          {},
          el('h3', {}, 's and e'),
          tileGrid({
            rows: [s, e],
            color: (v) => diverging(centered(v), eta1),
            describe: (i, j, idx, v) => `${i === 0 ? 's' : 'e'}[${j}] coefficient ${idx} = ${centered(v)}`,
            cell: 6,
            gap: 10,
            label: 'The secret vector s and the error vector e as heatmaps',
            rowLabels: ['s', 'e'],
          }),
          el(
            'div',
            { class: 'legend' },
            el('span', {}, el('i', { style: `background:${diverging(-eta1, eta1)}` }), `−${eta1}`),
            el('span', {}, el('i', { style: `background:${diverging(0, eta1)}` }), '0'),
            el('span', {}, el('i', { style: `background:${diverging(eta1, eta1)}` }), `+${eta1}`),
          ),
        ),
        el(
          'div',
          {},
          el('h3', {}, `all ${fmt.int(2 * k * 256)} coefficients`),
          histogram(
            bins.map((b) => ({ x: b.value, count: b.count, expected: b.expected, color: b.value === 0 ? COLORS.faint : diverging(b.value, eta1 * 1.4) })),
            { width: 300, height: 170, xLabel: fmt.signed, title: 'Histogram of the noise coefficients against the binomial distribution' },
          ),
          el('div', { class: 'legend' }, el('span', {}, '▮ observed'), el('span', {}, '○ expected')),
        ),
      ),
    ),
  );
  return root;
}
