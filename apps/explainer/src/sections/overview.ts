import { bytesEqual, type Exchange } from '../model.ts';
import { el, figure, fmt, hexGroups, html, section } from '../ui.ts';

export function overview(ex: Exchange): HTMLElement {
  const { params } = ex.kem;
  const same = bytesEqual(ex.aliceKey, ex.bobKey);
  const { root, body } = section('exchange', '00', 'The exchange at a glance');

  body.append(
    html(`<p>Alice generates a key pair and publishes the <em>encapsulation key</em>. Bob uses it to make a ciphertext and a 32-byte shared secret
      at the same time. Alice turns the ciphertext back into the same secret with her <em>decapsulation key</em>. Unlike Diffie-Hellman, the secret comes
      from Bob's randomness alone, bound to Alice's key by a hash; unlike RSA encryption, nobody chooses what the secret is.</p>`),
    figure(
      el(
        'div',
        { class: 'exchange' },
        el(
          'div',
          { class: 'party' },
          el('h3', {}, 'Alice'),
          el('p', { class: 'role' }, 'KeyGen, then Decaps'),
          el(
            'dl',
            { class: 'kv' },
            el('dt', {}, 'ek'),
            el('dd', {}, `${fmt.int(params.encapsulationKeyBytes)} bytes, public`),
            el('dt', {}, 'dk'),
            el('dd', {}, `${fmt.int(params.decapsulationKeyBytes)} bytes, secret`),
          ),
          el('p', { class: 'secret-label' }, 'her shared secret'),
          el('div', { class: 'hex', 'data-testid': 'secret-alice' }, hexGroups(ex.aliceKey)),
        ),
        el(
          'div',
          { class: 'wire' },
          el('div', { class: 'arrow' }, el('b', {}, 'ek →'), `${fmt.int(params.encapsulationKeyBytes)} bytes`),
          el('div', { class: 'arrow' }, el('b', {}, '← c'), `${fmt.int(params.ciphertextBytes)} bytes`),
        ),
        el(
          'div',
          { class: 'party' },
          el('h3', {}, 'Bob'),
          el('p', { class: 'role' }, 'Encaps'),
          el(
            'dl',
            { class: 'kv' },
            el('dt', {}, 'm'),
            el('dd', {}, '32 random bytes, never sent'),
            el('dt', {}, 'c'),
            el('dd', {}, `${fmt.int(params.ciphertextBytes)} bytes`),
          ),
          el('p', { class: 'secret-label' }, 'his shared secret'),
          el('div', { class: 'hex', 'data-testid': 'secret-bob' }, hexGroups(ex.bobKey)),
        ),
      ),
      el(
        'p',
        { class: 'figure__caption' },
        el('span', { class: `badge ${same ? 'badge--ok' : 'badge--bad'}`, 'data-testid': 'keys-match' }, same ? 'identical' : 'different'),
        ` ${params.name}, traced, in this tab: KeyGen ${fmt.ms(ex.timings.keygen)}, Encaps ${fmt.ms(ex.timings.encaps)}, Decaps ${fmt.ms(ex.timings.decaps)}. Recording the intermediate values makes each step slower than it would otherwise be.`,
      ),
    ),
    html(`<p class="note">Everything below is this one exchange. "New randomness" at the top draws fresh seeds and a fresh message and redraws every figure;
      "Copy link" gives a URL that reproduces exactly this run.</p>`),
  );
  return root;
}
