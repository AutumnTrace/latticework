// Polynomials drawn as 16 x 16 tiles: coefficient i at row i >> 4, column i & 15.

import type { Poly } from '@autumntrace/latticework/internals';
import { canvas, COLORS, hideTooltip, pointer, showTooltip } from './ui.ts';

export interface TileGrid {
  /** Polynomials by row, then column. */
  rows: Poly[][];
  color: (value: number) => string;
  /** Tooltip text for coefficient `index` of the polynomial at (row, col). */
  describe: (row: number, col: number, index: number, value: number) => string;
  cell?: number;
  gap?: number;
  label: string;
  /** Labels drawn above each column and left of each row. */
  colLabels?: string[];
  rowLabels?: string[];
}

export function tileGrid(spec: TileGrid): HTMLCanvasElement {
  const cell = spec.cell ?? 6;
  const gap = spec.gap ?? 10;
  const tile = 16 * cell;
  const left = spec.rowLabels ? 34 : 0;
  const top = spec.colLabels ? 18 : 0;
  const nRows = spec.rows.length;
  const nCols = Math.max(...spec.rows.map((r) => r.length));
  const width = left + nCols * tile + (nCols - 1) * gap;
  const height = top + nRows * tile + (nRows - 1) * gap;
  const { canvas: c, ctx } = canvas(width, height, spec.label);

  ctx.font = '11px ui-monospace, Menlo, Consolas, monospace';
  ctx.fillStyle = COLORS.muted;
  ctx.textBaseline = 'middle';
  spec.colLabels?.forEach((l, j) => {
    ctx.textAlign = 'center';
    ctx.fillText(l, left + j * (tile + gap) + tile / 2, 8);
  });
  spec.rowLabels?.forEach((l, i) => {
    ctx.textAlign = 'left';
    ctx.fillText(l, 0, top + i * (tile + gap) + tile / 2);
  });

  spec.rows.forEach((row, i) =>
    row.forEach((p, j) => {
      const x0 = left + j * (tile + gap);
      const y0 = top + i * (tile + gap);
      for (let k = 0; k < 256; k++) {
        ctx.fillStyle = spec.color(p[k]!);
        ctx.fillRect(x0 + (k & 15) * cell, y0 + (k >> 4) * cell, cell, cell);
      }
    }),
  );

  c.addEventListener('mousemove', (ev) => {
    const { x, y } = pointer(c, ev);
    const j = Math.floor((x - left) / (tile + gap));
    const i = Math.floor((y - top) / (tile + gap));
    const lx = x - left - j * (tile + gap);
    const ly = y - top - i * (tile + gap);
    const p = spec.rows[i]?.[j];
    if (!p || lx < 0 || ly < 0 || lx >= tile || ly >= tile) return hideTooltip();
    const index = Math.floor(ly / cell) * 16 + Math.floor(lx / cell);
    showTooltip(ev, spec.describe(i, j, index, p[index]!));
  });
  c.addEventListener('mouseleave', hideTooltip);
  return c;
}
