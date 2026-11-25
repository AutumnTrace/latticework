import './style.css';
import { KEMS, runExchange, type SetId } from './model.ts';
import { decapsulation, encapsulation, publicKey } from './sections/exchange.ts';
import { matrix, noise, seeds } from './sections/keygen.ts';
import { nttSection } from './sections/ntt.ts';
import { overview } from './sections/overview.ts';
import { tamperSection } from './sections/tamper.ts';
import { el, fromHex, hex } from './ui.ts';

interface State {
  set: SetId;
  d: Uint8Array;
  z: Uint8Array;
  m: Uint8Array;
}

const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

function fromHash(): State | null {
  const p = new URLSearchParams(location.hash.slice(1));
  const set = Number(p.get('set')) as SetId;
  const d = fromHex(p.get('d') ?? '');
  const z = fromHex(p.get('z') ?? '');
  const m = fromHex(p.get('m') ?? '');
  if (!(set in KEMS) || d?.length !== 32 || z?.length !== 32 || m?.length !== 32) return null;
  return { set, d, z, m };
}

function toHash(s: State): string {
  return `#set=${s.set}&d=${hex(s.d)}&z=${hex(s.z)}&m=${hex(s.m)}`;
}

let state: State = fromHash() ?? { set: 768, d: random(32), z: random(32), m: random(32) };

const sections = document.getElementById('sections')!;
const status = document.getElementById('status')!;
const picker = document.getElementById('set-picker')!;

const setButtons = (Object.keys(KEMS) as unknown as SetId[]).map((id) => {
  const b = el('button', { type: 'button', role: 'radio', 'aria-checked': 'false', 'data-testid': `set-${id}` }, `ML-KEM-${id}`);
  b.addEventListener('click', () => {
    state = { ...state, set: Number(id) as SetId };
    render();
  });
  picker.appendChild(b);
  return [Number(id), b] as const;
});

function render(): void {
  history.replaceState(null, '', toHash(state));
  for (const [id, b] of setButtons) b.setAttribute('aria-checked', String(id === state.set));
  const ex = runExchange(state.set, state.d, state.z, state.m);
  const scroll = window.scrollY;
  sections.replaceChildren(
    overview(ex),
    seeds(ex),
    matrix(ex),
    noise(ex),
    nttSection(ex),
    publicKey(ex),
    encapsulation(ex),
    decapsulation(ex),
    tamperSection(ex),
  );
  window.scrollTo({ top: scroll });
  document.body.dataset['ready'] = 'true';
}

document.getElementById('reroll')!.addEventListener('click', () => {
  state = { ...state, d: random(32), z: random(32), m: random(32) };
  render();
});

document.getElementById('copy-link')!.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(location.href);
    status.textContent = 'link copied';
  } catch {
    status.textContent = 'copy failed; the address bar has the link';
  }
  setTimeout(() => (status.textContent = ''), 2500);
});

window.addEventListener('hashchange', () => {
  const s = fromHash();
  if (s) {
    state = s;
    render();
  }
});

render();
