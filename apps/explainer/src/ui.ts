// Small DOM, canvas and colour helpers shared by the sections.

type Child = Node | string | number | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | number | boolean | undefined> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  append(node, ...children);
  return node;
}

export function append(node: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
}

/** Parse a small trusted HTML fragment (the section prose, written in this repo). */
export function html(markup: string): DocumentFragment {
  const t = document.createElement('template');
  t.innerHTML = markup.trim();
  return t.content;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

export function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number> = {}, ...children: Child[]): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  append(node, ...children);
  return node;
}

export function hex(bytes: Uint8Array, maxBytes = bytes.length): string {
  let s = '';
  const n = Math.min(maxBytes, bytes.length);
  for (let i = 0; i < n; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return n < bytes.length ? `${s}…` : s;
}

/** 64 hex digits as four groups of 16, for 32-byte secrets. */
export function hexGroups(bytes: Uint8Array): string {
  return hex(bytes).replace(/(.{16})(?=.)/g, '$1 ');
}

export function fromHex(s: string): Uint8Array | null {
  if (!/^(?:[0-9a-f]{2})*$/i.test(s)) return null;
  return Uint8Array.from(s.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
}

export const fmt = {
  int: (n: number) => n.toLocaleString('en-US'),
  ms: (n: number) => (n < 1 ? `${(n * 1000).toFixed(0)} µs` : `${n.toFixed(n < 10 ? 2 : 1)} ms`),
  pct: (n: number) => `${(100 * n).toFixed(1)}%`,
  signed: (n: number) => (n > 0 ? `+${n}` : n < 0 ? `−${-n}` : '0'),
};

/** A canvas sized in CSS pixels and backed at device resolution. */
export function canvas(width: number, height: number, label: string): { canvas: HTMLCanvasElement; ctx: CanvasRenderingContext2D } {
  const c = el('canvas', { role: 'img', 'aria-label': label });
  const dpr = Math.min(window.devicePixelRatio || 1, 3);
  c.width = Math.round(width * dpr);
  c.height = Math.round(height * dpr);
  c.style.width = `${width}px`;
  c.style.height = `${height}px`;
  const ctx = c.getContext('2d')!;
  ctx.scale(dpr, dpr);
  return { canvas: c, ctx };
}

/** Pointer position in the canvas's CSS pixel space. */
export function pointer(c: HTMLCanvasElement, ev: MouseEvent): { x: number; y: number } {
  const r = c.getBoundingClientRect();
  return { x: ((ev.clientX - r.left) / r.width) * parseFloat(c.style.width), y: ((ev.clientY - r.top) / r.height) * parseFloat(c.style.height) };
}

// ------------------------------------------------------------- colours

type Rgb = [number, number, number];

function lerpStops(stops: Rgb[], t: number): Rgb {
  const x = Math.min(Math.max(t, 0), 1) * (stops.length - 1);
  const i = Math.min(Math.floor(x), stops.length - 2);
  const f = x - i;
  const a = stops[i]!;
  const b = stops[i + 1]!;
  return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f];
}

const css = ([r, g, b]: Rgb) => `rgb(${r | 0},${g | 0},${b | 0})`;

// A cyclic map for values in Z_q: 0 and q - 1 are neighbours, so they get
// nearly the same colour. Dark at 0, blue at q/4, pale at q/2, amber at 3q/4.
const RING: Rgb[] = [
  [28, 32, 42],
  [110, 168, 254],
  [228, 231, 236],
  [242, 184, 75],
  [28, 32, 42],
];

/** Cyclic colour for a coefficient in [0, q), given as a fraction of q. */
export function ringColor(t: number): string {
  return css(lerpStops(RING, t - Math.floor(t)));
}

const NEG: Rgb = [240, 113, 138];
const ZERO: Rgb = [34, 40, 50];
const POS: Rgb = [90, 209, 179];

/** Diverging colour for a small signed value in [-max, max]. */
export function diverging(x: number, max: number): string {
  const t = Math.min(Math.abs(x) / max, 1);
  const end = x < 0 ? NEG : POS;
  return css([ZERO[0] + (end[0] - ZERO[0]) * t, ZERO[1] + (end[1] - ZERO[1]) * t, ZERO[2] + (end[2] - ZERO[2]) * t]);
}

export const COLORS = {
  text: '#dde2ea',
  muted: '#8d96a5',
  faint: '#5b6473',
  line: '#262d39',
  panel: '#151a22',
  panel2: '#1b212b',
  teal: '#5ad1b3',
  amber: '#f2b84b',
  rose: '#f0718a',
  blue: '#6ea8fe',
  violet: '#b39dfa',
};

// ------------------------------------------------------------- tooltip

const tip = () => document.getElementById('tooltip')!;

export function showTooltip(ev: MouseEvent, text: string): void {
  const t = tip();
  t.textContent = text;
  t.hidden = false;
  const pad = 14;
  const { innerWidth, innerHeight } = window;
  const r = t.getBoundingClientRect();
  let x = ev.clientX + pad;
  let y = ev.clientY + pad;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - pad;
  t.style.left = `${x}px`;
  t.style.top = `${y}px`;
}

export function hideTooltip(): void {
  tip().hidden = true;
}

// ------------------------------------------------------------- pieces

export function section(id: string, step: string, title: string): { root: HTMLElement; body: HTMLElement } {
  const body = el('div', { class: 'section__inner' }, el('h2', {}, el('span', { class: 'step' }, step), title));
  const root = el('section', { class: 'section', id, 'aria-labelledby': `${id}-title` }, body);
  body.querySelector('h2')!.id = `${id}-title`;
  return { root, body };
}

export function figure(...children: Child[]): HTMLElement {
  return el('div', { class: 'figure' }, ...children);
}

export interface LayoutPart {
  label: string;
  bytes: number;
  color: string;
}

/**
 * A bar showing how a byte string is laid out, widths proportional to size.
 * Parts too narrow for their label are named in the legend underneath.
 */
export function layoutBar(title: string, parts: LayoutPart[]): HTMLElement {
  const total = parts.reduce((a, p) => a + p.bytes, 0);
  return el(
    'div',
    {},
    el('p', { class: 'layout-label' }, `${title} · ${fmt.int(total)} bytes`),
    el(
      'div',
      { class: 'layout' },
      ...parts.map((p) =>
        el(
          'div',
          { style: `flex: ${p.bytes} 1 0; background: ${p.color}`, title: `${p.label}: ${fmt.int(p.bytes)} bytes` },
          p.bytes / total > 0.09 ? `${p.label} · ${fmt.int(p.bytes)}` : '',
        ),
      ),
    ),
    el('div', { class: 'layout-legend' }, ...parts.map((p) => el('span', {}, el('i', { style: `background:${p.color}` }), `${p.label} ${fmt.int(p.bytes)} B`))),
  );
}

export interface Bar {
  x: number;
  count: number;
  expected?: number;
  color?: string;
}

/**
 * A small SVG histogram. Bars are observed counts; dots, when given, are
 * expected counts. `markers` draws vertical lines at x positions.
 */
export function histogram(
  bars: Bar[],
  opts: {
    width: number;
    height: number;
    xLabel: (x: number) => string;
    labelEvery?: number;
    markers?: { x: number; label: string; color: string }[];
    barWidth?: number;
    xMin?: number;
    xMax?: number;
    title: string;
  },
): SVGSVGElement {
  const { width, height } = opts;
  const m = { top: 14, right: 10, bottom: 26, left: 10 };
  const xs = bars.map((b) => b.x);
  const xMin = opts.xMin ?? Math.min(...xs);
  const xMax = opts.xMax ?? Math.max(...xs);
  const maxY = Math.max(...bars.map((b) => Math.max(b.count, b.expected ?? 0)), 1);
  const plotW = width - m.left - m.right;
  const plotH = height - m.top - m.bottom;
  const step = bars.length > 1 ? plotW / (xMax - xMin + (opts.barWidth ?? 1)) : plotW;
  const bw = Math.max(1, step * (opts.barWidth ?? 1) * 0.82);
  const X = (x: number) => m.left + (x - xMin) * step + (step * (opts.barWidth ?? 1)) / 2;
  const Y = (y: number) => m.top + plotH - (y / maxY) * plotH;

  const root = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': opts.title });
  root.appendChild(svg('line', { x1: m.left, x2: width - m.right, y1: m.top + plotH + 0.5, y2: m.top + plotH + 0.5, stroke: COLORS.line }));
  bars.forEach((b, i) => {
    const h = (b.count / maxY) * plotH;
    root.appendChild(
      svg(
        'rect',
        { x: X(b.x) - bw / 2, y: m.top + plotH - h, width: bw, height: h, fill: b.color ?? COLORS.blue, rx: Math.min(2, bw / 4) },
        svg('title', {}, `${opts.xLabel(b.x)}: ${b.count}${b.expected !== undefined ? ` (expected ${b.expected.toFixed(1)})` : ''}`),
      ),
    );
    if (b.expected !== undefined)
      root.appendChild(svg('circle', { cx: X(b.x), cy: Y(b.expected), r: 3.2, fill: 'none', stroke: COLORS.text, 'stroke-width': 1.4 }));
    if (i % (opts.labelEvery ?? 1) === 0)
      root.appendChild(svg('text', { x: X(b.x), y: height - 8, 'text-anchor': 'middle', 'font-size': 11, fill: COLORS.muted }, opts.xLabel(b.x)));
  });
  for (const mk of opts.markers ?? []) {
    const x = X(mk.x);
    root.appendChild(svg('line', { x1: x, x2: x, y1: m.top - 4, y2: m.top + plotH, stroke: mk.color, 'stroke-dasharray': '3 3' }));
    root.appendChild(
      svg('text', { x, y: m.top - 4, 'text-anchor': x > width / 2 ? 'end' : 'start', dx: x > width / 2 ? -4 : 4, 'font-size': 11, fill: mk.color }, mk.label),
    );
  }
  return root;
}
