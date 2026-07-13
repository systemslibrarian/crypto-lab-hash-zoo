import { describeBitFlip, inputBitStrip, maxBitPosition } from './avalanche';
import {
  avalancheAnalysis,
  avalancheDistribution,
  hashAll,
  lengthExtend,
  oneLineHash,
  paddingInfo,
  type AvalanchePerAlgorithm,
  type HashResults,
} from './hasher';

const defaultMessage = 'The quick brown fox jumps over the lazy dog';

// Uniform, non-decorative byte spans. The previous byte-N (index mod 8)
// coloring looked meaningful but wasn't, inviting learners to hunt for a
// pattern that didn't exist; per-byte color now only appears in the avalanche
// heatmap where it actually encodes how many bits changed.
function renderByteSpans(hex: string): string {
  const chunks = hex.match(/.{1,2}/g) ?? [];
  return chunks.map((chunk) => `<span class="byte">${chunk}</span>`).join('');
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatMicros(ms: number): string {
  return `${(ms * 1000).toFixed(2)} µs`;
}

function makeHashRows(results: HashResults): string {
  return `
    <tr>
      <th scope="row">Output (hex)</th>
      <td data-label="SHA-256">
        <div class="hex-wrap">${renderByteSpans(results.sha256.hex)}</div>
        <button class="copy-btn" type="button" data-copy="${results.sha256.hex}" aria-label="Copy SHA-256 hash">Copy</button>
      </td>
      <td data-label="SHA3-256">
        <div class="hex-wrap">${renderByteSpans(results.sha3.hex)}</div>
        <button class="copy-btn" type="button" data-copy="${results.sha3.hex}" aria-label="Copy SHA3-256 hash">Copy</button>
      </td>
      <td data-label="BLAKE3">
        <div class="hex-wrap">${renderByteSpans(results.blake3.hex)}</div>
        <button class="copy-btn" type="button" data-copy="${results.blake3.hex}" aria-label="Copy BLAKE3 hash">Copy</button>
      </td>
    </tr>
    <tr>
      <th scope="row">Output size</th>
      <td data-label="SHA-256">256 bits</td>
      <td data-label="SHA3-256">256 bits</td>
      <td data-label="BLAKE3">256 bits</td>
    </tr>
    <tr>
      <th scope="row">Internal state <span class="th-note">(running memory between blocks)</span></th>
      <td data-label="SHA-256">256-bit chaining value <span class="td-note">(all of it is published as the digest)</span></td>
      <td data-label="SHA3-256">1600-bit state, split 1088 rate | 512 capacity <span class="td-note">(the 512 stays hidden)</span></td>
      <td data-label="BLAKE3">256-bit chaining value per tree node</td>
    </tr>
    <tr>
      <th scope="row">Construction <span class="th-note">(how blocks are combined)</span></th>
      <td data-label="SHA-256">Merkle-Damgard <span class="td-note">(one block after another)</span></td>
      <td data-label="SHA3-256">Sponge <span class="td-note">(absorb then squeeze)</span></td>
      <td data-label="BLAKE3">Binary tree <span class="td-note">(leaves combined in parallel)</span></td>
    </tr>
  `;
}

function makeTimingHtml(results: HashResults): string {
  return `
    <div class="timing-grid">
      <div class="timing-cell"><span class="timing-algo">SHA-256</span><span class="timing-num">${formatMicros(results.sha256.timeMs)}</span></div>
      <div class="timing-cell"><span class="timing-algo">SHA3-256</span><span class="timing-num">${formatMicros(results.sha3.timeMs)}</span></div>
      <div class="timing-cell"><span class="timing-algo">BLAKE3</span><span class="timing-num">${formatMicros(results.blake3.timeMs)}</span></div>
    </div>
  `;
}

// Heatmap: for each of the 32 output bytes, count how many of its 8 bits
// changed (0..8) so the color carries information (uniform diffusion) instead
// of the old decorative index-mod-8 tint.
function perByteChanges(changedBitMap: boolean[]): number[] {
  const counts: number[] = [];
  for (let byteIndex = 0; byteIndex < 32; byteIndex += 1) {
    let n = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      if (changedBitMap[byteIndex * 8 + bit]) n += 1;
    }
    counts.push(n);
  }
  return counts;
}

function renderGrid(data: AvalanchePerAlgorithm, id: string): string {
  const pct = data.diffPercent;
  const delta = Math.abs(pct - 50);
  const quality = delta <= 6 ? 'ideal' : delta <= 12 ? 'good' : 'off';
  const heat = perByteChanges(data.changedBitMap);
  return `
    <div class="algo-card">
      <h3>${id.toUpperCase()}</h3>
      <p class="algo-meta">Changed: <strong>${data.diffBits}/256</strong> bits (${pct.toFixed(1)}%)</p>
      <div class="meter is-${quality}" aria-hidden="true">
        <div class="meter-fill" style="width:${pct.toFixed(1)}%"></div>
        <span class="meter-mark"></span>
      </div>
      <div class="bit-grid" role="img" aria-label="${id}: ${data.diffBits} of 256 output bits changed, ${pct.toFixed(1)} percent, ${delta <= 6 ? 'close to the ideal 50 percent' : 'away from the ideal 50 percent'}">
        ${data.changedBitMap
          .map(
            (changed, index) =>
              `<div class="bit-cell ${changed ? 'changed' : 'same'}" style="transition-delay:${index * 2}ms" title="Bit ${index + 1}: ${changed ? 'changed' : 'same'}"></div>`,
          )
          .join('')}
      </div>
      <p class="heatmap-caption">Per-byte heatmap — how many of each output byte's 8 bits changed. Even, near-4/8 shading everywhere is the goal (uniform diffusion).</p>
      <div class="byte-heatmap" role="img" aria-label="${id}: per-byte change heatmap. Each of 32 output bytes changed between ${Math.min(...heat)} and ${Math.max(...heat)} of its 8 bits.">
        ${heat
          .map(
            (n, index) =>
              `<div class="heat-cell heat-${n}" title="Byte ${index + 1}: ${n}/8 bits changed"></div>`,
          )
          .join('')}
      </div>
    </div>
  `;
}

function buildAppHtml(): string {
  return `
    <a href="#hash-comparison" class="skip-link">Skip to main content</a>
    <button id="theme-toggle" type="button" aria-label="Switch to light mode" title="Toggle color theme"></button>

    <main>
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Hash Zoo</h1>
        <p class="cl-hero-sub">SHA-256 · SHA3-256 · BLAKE3</p>
        <p class="cl-hero-desc">Hashes the same message through Merkle-Damgard, sponge, and tree constructions side-by-side, then flips a single input bit so you can watch each design's avalanche scatter across the output.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Hashes anchor passwords, file integrity, signatures, and blockchains. A strong avalanche is what makes them collision-resistant and hard to forge — and choosing the right construction decides whether you also dodge length-extension attacks.</p>
      </aside>
    </header>

    <section class="panel" id="hash-intro">
      <h2>Start here - What is a hash?</h2>
      <p class="intro-lead">A <strong>hash function</strong> takes any input and boils it down to a short, fixed-size fingerprint. Three plain rules define a good one:</p>
      <ul class="intro-rules">
        <li><strong>Deterministic</strong> — the same input always gives the same fingerprint.</li>
        <li><strong>Fixed-size</strong> — a tweet or a movie both come out as the same 256-bit tag.</li>
        <li><strong>One-way &amp; unpredictable</strong> — you can't run it backwards to the input, and changing anything scrambles the whole output.</li>
      </ul>
      <div class="intro-live">
        <label for="intro-input">Try it — type anything:</label>
        <input id="intro-input" type="text" value="hello" autocomplete="off" spellcheck="false" />
        <p class="intro-output" aria-live="polite">
          <span class="intro-arrow" aria-hidden="true">SHA-256 →</span>
          <code id="intro-hash"></code>
        </p>
        <p class="intro-hint">Edit one letter and watch the whole fingerprint change. That total scramble from a tiny edit is the <em>avalanche effect</em>, explored in Section B. This page then compares three different ways of building that fingerprint.</p>
      </div>
    </section>

    <section class="panel" id="hash-comparison">
      <h2>Section A - Hash Comparison</h2>
      <p class="section-lead">Now the three-way comparison. Each column is a real hash function computing a 256-bit digest of your message in your browser. They look like the same kind of random noise, yet they are built completely differently (Sections C and the info panel unpack how).</p>
      <label for="message-input">Message</label>
      <textarea id="message-input" rows="4">${defaultMessage}</textarea>
      <div class="button-row">
        <button id="hash-btn" type="button">Hash All Three</button>
        <button id="padding-btn" class="ghost-btn" type="button">Padding info</button>
      </div>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Hash comparison results">
        <table aria-label="Hash comparison results">
          <caption class="sr-only">Side-by-side comparison of SHA-256, SHA3-256, and BLAKE3</caption>
          <thead>
            <tr>
              <td></td>
              <th scope="col">SHA-256</th>
              <th scope="col">SHA3-256</th>
              <th scope="col">BLAKE3</th>
            </tr>
          </thead>
          <tbody id="hash-results"></tbody>
        </table>
      </div>
      <p class="consistency">Same input -> same output.</p>
      <details class="timing-details">
        <summary>Show indicative timing (not a benchmark)</summary>
        <div id="timing-grid-host"></div>
        <p class="timing-note">In-browser average over 100 iterations, in microseconds. Indicative only: JIT warmup, garbage collection, CPU throttling, and other tabs make single-digit-microsecond numbers noisy, so treat them as a rough feel for relative cost rather than a benchmark. For real comparisons, measure a native build (for example <code>b3sum</code> vs <code>openssl</code>) on large inputs.</p>
      </details>
    </section>

    <section class="panel" id="avalanche-section">
      <h2>Section B - Avalanche Effect</h2>
      <p class="section-lead">The headline property: flip <strong>one</strong> input bit and about <strong>half</strong> of the 256 output bits flip — unpredictably. Watch the cause (one input bit, left) and the effect (the output storm, right) in the same view.</p>
      <p id="message-preview"></p>
      <div class="slider-row">
        <label for="bit-slider">Bit position to flip</label>
        <output id="bit-value" for="bit-slider" class="slider-value">0</output>
      </div>
      <input id="bit-slider" type="range" min="0" value="0" step="1" aria-describedby="bit-label" />
      <p id="bit-label"></p>

      <div class="cause-effect">
        <div class="cause-panel">
          <h3 class="mini-head">Cause: input bits</h3>
          <p class="mini-note">One bit is flipped (highlighted). Everything else is untouched.</p>
          <div id="input-strip" class="input-strip" role="img" tabindex="0" aria-label="Input bit strip"></div>
        </div>
      </div>

      <button id="analyze-btn" type="button">Analyze Avalanche</button>
      <ul class="legend" aria-label="Avalanche grid legend">
        <li><span class="legend-swatch swatch-changed" aria-hidden="true"></span> Changed bit (striped)</li>
        <li><span class="legend-swatch swatch-same" aria-hidden="true"></span> Unchanged bit (solid)</li>
        <li><span class="legend-swatch swatch-ideal" aria-hidden="true"></span> Meter mark = ideal 50%</li>
      </ul>
      <p class="mini-head effect-head">Effect: output bits (~50% flip)</p>
      <div id="avalanche-grids" class="avalanche-wrap">
        <p class="empty-state">Scroll here or press <strong>Analyze Avalanche</strong> to compute the bit-change grids.</p>
      </div>
      <p class="ideal-note">A strong hash flips roughly 50% of output bits when a single input bit changes. Each card's meter shows how close it lands to that ideal.</p>

      <div class="dist-block">
        <h3 class="mini-head">Is ~50% just luck? Flip every bit and see.</h3>
        <p class="mini-note">One flip landing near 50% could be coincidence. This flips <em>every</em> input bit in turn and plots the distribution of output-diff percentages. A strong hash clusters them tightly around 50% — that tight cluster is the security-relevant law, not any single result.</p>
        <div class="dist-controls">
          <label for="dist-algo">Algorithm</label>
          <select id="dist-algo">
            <option value="sha256">SHA-256</option>
            <option value="sha3">SHA3-256</option>
            <option value="blake3">BLAKE3</option>
          </select>
          <button id="dist-btn" type="button">Run every-bit sweep</button>
        </div>
        <div id="dist-result" class="dist-result"></div>
      </div>
    </section>

    <section class="panel" id="construction-section">
      <h2>Section C - Construction Comparison</h2>
      <p class="section-lead">Same 256-bit output, three different internal machines. The single most consequential difference: what the final digest reveals about the hash's <em>internal state</em>. Merkle-Damgard publishes its whole state as the digest — so an attacker can resume from it. The sponge withholds a secret <span class="term">capacity <span class="term-def">(the part of the state never exposed in the output)</span></span> lane, so they can't.</p>
      <div class="diagram-row">
        <article class="diagram-card">
          <h3>SHA-256 (Merkle-Damgaard)</h3>
          <svg viewBox="0 0 520 190" role="img" aria-labelledby="md-title md-desc">
            <title id="md-title">SHA-256 Merkle-Damgaard construction</title>
            <desc id="md-desc">The padded message is split into 512-bit blocks that are compressed one after another, each block mixing into the running chaining value that starts from a fixed IV. The final chaining value is the output hash, which is what makes bare Merkle-Damgaard vulnerable to length-extension attacks.</desc>
            <rect x="12" y="70" width="90" height="40" rx="8"/><text x="57" y="95">Message</text>
            <rect x="128" y="70" width="120" height="40" rx="8"/><text x="188" y="95">Pad 512b</text>
            <rect x="274" y="20" width="100" height="40" rx="8"/><text x="324" y="45">IV</text>
            <rect x="274" y="70" width="100" height="40" rx="8"/><text x="324" y="95">Block 1</text>
            <rect x="396" y="70" width="100" height="40" rx="8"/><text x="446" y="95">Block 2</text>
            <line x1="102" y1="90" x2="128" y2="90"/><line x1="248" y1="90" x2="274" y2="90"/>
            <line x1="374" y1="90" x2="396" y2="90"/><line x1="324" y1="60" x2="324" y2="70"/>
            <rect x="396" y="130" width="100" height="40" rx="8"/><text x="446" y="155">Final Hash</text>
            <line x1="446" y1="110" x2="446" y2="130"/>
          </svg>
          <p>Length extension attack possible on bare MD.</p>
        </article>

        <article class="diagram-card">
          <h3>SHA-3 (Sponge)</h3>
          <svg viewBox="0 0 520 190" role="img" aria-labelledby="sponge-title sponge-desc">
            <title id="sponge-title">SHA-3 sponge construction</title>
            <desc id="sponge-desc">Input is absorbed into a 1600-bit state split into a 1088-bit rate and a 512-bit capacity, then output is squeezed out. Because attackers never see the secret capacity portion, the sponge resists length-extension attacks by design.</desc>
            <rect x="16" y="70" width="90" height="40" rx="8"/><text x="61" y="95">Message</text>
            <rect x="132" y="70" width="120" height="40" rx="8"/><text x="192" y="95">Absorb</text>
            <rect x="278" y="30" width="200" height="120" rx="10"/>
            <line x1="278" y1="95" x2="478" y2="95"/>
            <text x="378" y="82">Rate 1088</text><text x="378" y="122">Capacity 512</text>
            <rect x="132" y="130" width="120" height="40" rx="8"/><text x="192" y="155">Squeeze</text>
            <line x1="106" y1="90" x2="132" y2="90"/><line x1="252" y1="90" x2="278" y2="90"/>
            <line x1="278" y1="150" x2="252" y2="150"/><line x1="132" y1="150" x2="106" y2="150"/>
            <text x="26" y="155">256-bit out</text>
          </svg>
          <p>No length extension. Rate/capacity trade-off.</p>
        </article>

        <article class="diagram-card">
          <h3>BLAKE3 (Tree)</h3>
          <svg viewBox="0 0 520 190" role="img" aria-labelledby="tree-title tree-desc">
            <title id="tree-title">BLAKE3 binary tree construction</title>
            <desc id="tree-desc">The message is divided into 1024-byte leaf chunks hashed independently, then pairs of chaining values are combined up a binary tree to a single root hash. Independent leaves can be hashed in parallel across CPU cores and SIMD lanes, which makes BLAKE3 the fastest of the three.</desc>
            <circle cx="60" cy="150" r="14"/><circle cx="150" cy="150" r="14"/>
            <circle cx="240" cy="150" r="14"/><circle cx="330" cy="150" r="14"/>
            <circle cx="105" cy="100" r="14"/><circle cx="285" cy="100" r="14"/>
            <circle cx="195" cy="50" r="16"/>
            <line x1="60" y1="136" x2="105" y2="114"/><line x1="150" y1="136" x2="105" y2="114"/>
            <line x1="240" y1="136" x2="285" y2="114"/><line x1="330" y1="136" x2="285" y2="114"/>
            <line x1="105" y1="86" x2="195" y2="66"/><line x1="285" y1="86" x2="195" y2="66"/>
            <text x="28" y="175">Leaf chunks</text><text x="158" y="28">Root hash</text>
          </svg>
          <p>Parallelizable, SIMD-friendly, fastest of the three.</p>
        </article>
      </div>

      <div class="lext-demo">
        <h3>Watch length extension actually forge a hash (SHA-256)</h3>
        <p class="mini-note">This is the flagship claim made concrete. Imagine a server that authenticates a message with <code>tag = SHA-256(secret ‖ message)</code> and publishes <code>tag</code>. You (the attacker) never learn <code>secret</code> — only its byte length and <code>tag</code>. Because bare Merkle-Damgard <em>is</em> its internal state, you can resume from <code>tag</code>, append your own bytes, and produce a tag that validates. Every hash below is computed live in your browser; the forgery is proven by recomputing SHA-256 over the reconstructed message from scratch.</p>
        <div class="lext-controls">
          <div class="lext-field">
            <label for="lext-secret">Secret (you would NOT see this — used only to build the proof)</label>
            <input id="lext-secret" type="text" value="secret-key||user=alice&role=guest" autocomplete="off" spellcheck="false" />
          </div>
          <div class="lext-field">
            <label for="lext-append">Data you append (attacker-controlled)</label>
            <input id="lext-append" type="text" value="&role=admin" autocomplete="off" spellcheck="false" />
          </div>
          <button id="lext-btn" type="button">Forge extended hash</button>
        </div>
        <div id="lext-result" class="lext-result" aria-live="polite"></div>
        <p class="mini-note lext-defense"><strong>The fix:</strong> don't use bare <code>SHA-256(secret ‖ message)</code> as a MAC. Use <span class="term">HMAC <span class="term-def">(keyed hash that mixes the secret on an inner and an outer pass, so the published tag is not a resumable internal state)</span></span>, or a sponge/tree hash (SHA-3, BLAKE3) whose digest withholds internal state. The sponge diagram above shows the withheld capacity lane that makes this same attack impossible.</p>
      </div>
    </section>

    <section class="panel" id="info-panel">
      <h2>Info Panel</h2>
      <div class="tabs" role="tablist" aria-label="Hash construction info">
        <button class="tab is-active" role="tab" aria-selected="true" aria-controls="panel-md" id="tab-md" data-tab="md">Merkle-Damgaard (SHA-256)</button>
        <button class="tab" role="tab" aria-selected="false" aria-controls="panel-sponge" id="tab-sponge" data-tab="sponge">Sponge Construction (SHA-3)</button>
        <button class="tab" role="tab" aria-selected="false" aria-controls="panel-tree" id="tab-tree" data-tab="tree">Tree Hashing (BLAKE3)</button>
        <button class="tab" role="tab" aria-selected="false" aria-controls="panel-choose" id="tab-choose" data-tab="choose">Choosing a Hash Function</button>
      </div>
      <div class="tab-panel is-active" role="tabpanel" id="panel-md" aria-labelledby="tab-md" data-panel="md">
        <p>SHA-256 processes the padded message one 512-bit block at a time. Each block updates a running <span class="term">chaining value <span class="term-def">(the state carried from block to block)</span></span> that starts from a fixed <span class="term">IV <span class="term-def">(initialization vector — a constant starting value)</span></span>. The final chaining value <em>is</em> the digest, which is exactly why bare Merkle-Damgard leaks enough state for a length-extension attack. HMAC-SHA256 stays safe because the secret key is mixed on both an inner and an outer pass, so the tag is not a resumable state.</p>
        <details class="advanced">
          <summary>Advanced</summary>
          <p>The block compression uses a <span class="term">Davies-Meyer <span class="term-def">(build a compression function from a block cipher, feeding the previous state back in)</span></span> construction over 64 rounds, with IV and round constants taken from the fractional parts of square roots and cube roots of the first primes.</p>
        </details>
      </div>
      <div class="tab-panel" role="tabpanel" id="panel-sponge" aria-labelledby="tab-sponge" data-panel="sponge">
        <p>SHA3-256 is a <span class="term">sponge <span class="term-def">(absorb input, then squeeze output, mixing a large fixed state)</span></span>. Its state is split into a <span class="term">rate <span class="term-def">(the part input touches and output comes from)</span></span> of 1088 bits and a <span class="term">capacity <span class="term-def">(a hidden reserve never exposed in the output)</span></span> of 512 bits. Because the capacity is withheld, an attacker cannot reconstruct the internal state from the digest, so the sponge resists length extension by design.</p>
        <details class="advanced">
          <summary>Advanced</summary>
          <p>The permutation is <span class="term">Keccak-f[1600] <span class="term-def">(the 1600-bit fixed permutation applied each round)</span></span>. Rate + capacity always sum to the 1600-bit state width; the capacity size sets the security level.</p>
        </details>
      </div>
      <div class="tab-panel" role="tabpanel" id="panel-tree" aria-labelledby="tab-tree" data-panel="tree">
        <p>BLAKE3 splits the message into 1024-byte leaf chunks, hashes each independently, then combines pairs of <span class="term">chaining values <span class="term-def">(each node's running state)</span></span> up a binary tree to a single root. Because leaves are independent, they hash in parallel across CPU cores.</p>
        <details class="advanced">
          <summary>Advanced</summary>
          <p>The tree is Bao-compatible and supports an <span class="term">XOF <span class="term-def">(extendable-output function — squeeze arbitrarily many output bytes)</span></span> plus keyed and key-derivation (KDF) modes, and maps cleanly onto <span class="term">SIMD <span class="term-def">(single-instruction-multiple-data CPU lanes)</span></span>.</p>
        </details>
      </div>
      <div class="tab-panel" role="tabpanel" id="panel-choose" aria-labelledby="tab-choose" data-panel="choose">
        <ul>
          <li>Integrity check, fast: BLAKE3</li>
          <li>Password hashing: Argon2id (not these hash functions)</li>
          <li>HMAC/PRF: SHA-256 or SHA-3 (BLAKE3 is also viable)</li>
          <li>NIST compliance required: SHA-256 or SHA-3</li>
          <li>Length extension concern without HMAC: SHA-3 or BLAKE3</li>
        </ul>
      </div>
      <details>
        <summary>Why this matters</summary>
        <p>SHA-256 and SHA-3 produce the same output size and both look like random noise, but their internal designs are completely different. SHA-2 uses a sequential Merkle-Damgaard construction that processes blocks one at a time. SHA-3 uses a sponge that absorbs input and squeezes output, making it immune to length extension attacks by design. BLAKE3 goes further: it is a binary tree of hashes, so it can be computed in parallel across CPU cores. Understanding the construction tells you which attack surface you are accepting.</p>
      </details>
    </section>
    </main>

    <footer class="panel footer-panel">
      <nav aria-label="Related demos">
        Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">crypto-lab-babel-hash</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/" target="_blank" rel="noreferrer">crypto-lab-merkle-vault</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-collision-vault/" target="_blank" rel="noreferrer">crypto-lab-collision-vault</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-mac-race/" target="_blank" rel="noreferrer">crypto-lab-mac-race</a>
        <a href="https://systemslibrarian.github.io/crypto-lab-kdf-chain/" target="_blank" rel="noreferrer">crypto-lab-kdf-chain</a>
      </nav>
      <nav>
        <a href="https://systemslibrarian.github.io/crypto-lab/babel-hash/" target="_blank" rel="noreferrer">babel-hash</a>
        <a href="https://systemslibrarian.github.io/crypto-lab/kdf-chain/" target="_blank" rel="noreferrer">kdf-chain</a>
        <a href="https://systemslibrarian.github.io/crypto-lab/corrupted-oracle/" target="_blank" rel="noreferrer">corrupted-oracle</a>
        <a href="https://systemslibrarian.github.io/crypto-lab/phantom-vault/" target="_blank" rel="noreferrer">phantom-vault</a>
      </nav>
    </footer>

    <dialog id="padding-modal" aria-labelledby="padding-modal-title">
      <h3 id="padding-modal-title">Padding Details</h3>
      <pre id="padding-content"></pre>
      <button id="close-modal" type="button">Close</button>
    </dialog>
    <div id="aria-live-region" class="sr-only" aria-live="polite" aria-atomic="true"></div>
  `;
}

function wireTabs(root: HTMLElement): void {
  const tabs = Array.from(root.querySelectorAll<HTMLButtonElement>('.tab'));
  const panels = Array.from(root.querySelectorAll<HTMLElement>('.tab-panel'));

  function activateTab(tab: HTMLButtonElement): void {
    tabs.forEach((button) => {
      button.classList.remove('is-active');
      button.setAttribute('aria-selected', 'false');
      button.setAttribute('tabindex', '-1');
    });
    panels.forEach((panel) => panel.classList.remove('is-active'));

    tab.classList.add('is-active');
    tab.setAttribute('aria-selected', 'true');
    tab.removeAttribute('tabindex');
    tab.focus();

    const target = tab.dataset.tab;
    root.querySelector<HTMLElement>(`.tab-panel[data-panel="${target}"]`)?.classList.add('is-active');
  }

  tabs.forEach((tab, index) => {
    if (!tab.classList.contains('is-active')) {
      tab.setAttribute('tabindex', '-1');
    }
    tab.addEventListener('click', () => activateTab(tab));
    tab.addEventListener('keydown', (event: KeyboardEvent) => {
      let nextIndex = index;
      if (event.key === 'ArrowRight') { nextIndex = (index + 1) % tabs.length; }
      else if (event.key === 'ArrowLeft') { nextIndex = (index - 1 + tabs.length) % tabs.length; }
      else if (event.key === 'Home') { nextIndex = 0; }
      else if (event.key === 'End') { nextIndex = tabs.length - 1; }
      else { return; }
      event.preventDefault();
      activateTab(tabs[nextIndex]);
    });
  });
}

function announce(message: string): void {
  const liveRegion = document.getElementById('aria-live-region');
  if (!liveRegion) return;
  liveRegion.textContent = '';
  setTimeout(() => {
    liveRegion.textContent = message;
  }, 50);
}

async function copyHash(event: Event): Promise<void> {
  const target = event.target as HTMLElement | null;
  if (!target || !target.classList.contains('copy-btn')) {
    return;
  }
  const hex = target.getAttribute('data-copy') ?? '';
  try {
    await navigator.clipboard.writeText(hex);
    target.textContent = 'Copied';
    announce('Hash copied to clipboard');
  } catch {
    target.textContent = 'Failed';
    announce('Copy failed');
  }
  setTimeout(() => {
    target.textContent = 'Copy';
  }, 900);
}

function renderInputStrip(host: HTMLElement, message: string, bitPosition: number): void {
  const strip = inputBitStrip(message, bitPosition);
  if (strip.totalBits === 0) {
    host.innerHTML = '<p class="empty-state">Add a message above to see its input bits.</p>';
    host.setAttribute('aria-label', 'Input bit strip: message is empty');
    return;
  }
  const truncated = strip.bits.length < strip.totalBits;
  host.setAttribute(
    'aria-label',
    `Input bit strip: ${strip.totalBits} bits, bit ${bitPosition} flipped (highlighted).` +
      (truncated ? ' Showing the first bits only.' : ''),
  );
  host.innerHTML =
    strip.bits
      .map(
        (b) =>
          `<span class="ibit ${b.value ? 'ibit-1' : 'ibit-0'}${b.flipped ? ' ibit-flip' : ''}" title="${b.flipped ? 'flipped input bit' : `input bit = ${b.value}`}">${b.value}</span>`,
      )
      .join('') +
    (truncated ? '<span class="ibit-more">…</span>' : '');
}

function renderDistribution(host: HTMLElement, message: string, algo: 'sha256' | 'sha3' | 'blake3'): void {
  if (message.length === 0) {
    host.innerHTML = '<p class="empty-state">Add a message above to run the sweep.</p>';
    return;
  }
  const dist = avalancheDistribution(message, algo);
  const maxCount = Math.max(1, ...dist.buckets);
  const bars = dist.buckets
    .map((count, i) => {
      const lo = (i * dist.bucketSize).toFixed(0);
      const hi = ((i + 1) * dist.bucketSize).toFixed(0);
      const h = Math.round((count / maxCount) * 100);
      const near50 = i * dist.bucketSize <= 50 && (i + 1) * dist.bucketSize > 50;
      return `<div class="hist-bar${near50 ? ' hist-mid' : ''}" style="height:${h}%" title="${lo}–${hi}% output diff: ${count} flips"></div>`;
    })
    .join('');
  host.innerHTML = `
    <p class="dist-summary">${dist.percents.length} single-bit flips · mean <strong>${dist.mean.toFixed(1)}%</strong> · range ${dist.min.toFixed(1)}–${dist.max.toFixed(1)}% · the 50% column is highlighted.</p>
    <div class="hist" role="img" aria-label="${algo}: distribution of output-diff percent over ${dist.percents.length} single-bit input flips. Mean ${dist.mean.toFixed(1)} percent, range ${dist.min.toFixed(1)} to ${dist.max.toFixed(1)} percent, tightly clustered near 50 percent.">${bars}</div>
    <div class="hist-axis"><span>0%</span><span>50%</span><span>100%</span></div>
  `;
}

function renderLengthExtension(host: HTMLElement, secret: string, append: string): void {
  if (secret.length === 0) {
    host.innerHTML = '<p class="empty-state">Enter a non-empty secret to run the forgery.</p>';
    return;
  }
  const r = lengthExtend(secret, append);
  const verdict = r.verified
    ? '<span class="lext-ok">✓ VERIFIED — the forged hash equals SHA-256 of the reconstructed message, computed from scratch. A real, valid forgery.</span>'
    : '<span class="lext-bad">✗ Mismatch (unexpected).</span>';
  host.innerHTML = `
    <dl class="lext-facts">
      <dt>1. Published tag (all you legitimately hold)</dt>
      <dd><code>${r.originalDigest}</code><br><span class="lext-meta">plus the length: ${r.originalLen} bytes. The secret bytes themselves are never used to build this forgery.</span></dd>
      <dt>2. Glue padding you can reconstruct from the length alone</dt>
      <dd><code>${r.gluePaddingHex}</code></dd>
      <dt>3. Your appended bytes</dt>
      <dd><code>${escapeHtml(r.appended)}</code></dd>
      <dt>4. Forged tag (resumed from the published tag, secret never seen)</dt>
      <dd><code class="lext-forged">${r.forgedHash}</code></dd>
      <dt>5. Independent check: SHA-256(secret ‖ glue ‖ append) from scratch</dt>
      <dd><code>${r.verifyHash}</code></dd>
    </dl>
    <p class="lext-verdict">${verdict}</p>
  `;
}

export function initHashZoo(): void {
  const app = document.querySelector<HTMLDivElement>('#app');
  if (!app) {
    return;
  }

  app.innerHTML = buildAppHtml();

  const messageInput = app.querySelector<HTMLTextAreaElement>('#message-input');
  const hashBtn = app.querySelector<HTMLButtonElement>('#hash-btn');
  const resultsBody = app.querySelector<HTMLTableSectionElement>('#hash-results');
  const themeToggle = app.querySelector<HTMLButtonElement>('#theme-toggle');
  const slider = app.querySelector<HTMLInputElement>('#bit-slider');
  const bitValue = app.querySelector<HTMLOutputElement>('#bit-value');
  const bitLabel = app.querySelector<HTMLParagraphElement>('#bit-label');
  const liveRegion = app.querySelector<HTMLElement>('#aria-live-region');
  const messagePreview = app.querySelector<HTMLParagraphElement>('#message-preview');
  const analyzeBtn = app.querySelector<HTMLButtonElement>('#analyze-btn');
  const grids = app.querySelector<HTMLDivElement>('#avalanche-grids');
  const paddingBtn = app.querySelector<HTMLButtonElement>('#padding-btn');
  const modal = app.querySelector<HTMLDialogElement>('#padding-modal');
  const closeModalBtn = app.querySelector<HTMLButtonElement>('#close-modal');
  const paddingContent = app.querySelector<HTMLElement>('#padding-content');

  // New teaching elements (optional — guarded individually so a missing one
  // never breaks the core comparison/avalanche experience).
  const introInput = app.querySelector<HTMLInputElement>('#intro-input');
  const introHash = app.querySelector<HTMLElement>('#intro-hash');
  const timingHost = app.querySelector<HTMLElement>('#timing-grid-host');
  const inputStripHost = app.querySelector<HTMLElement>('#input-strip');
  const distAlgo = app.querySelector<HTMLSelectElement>('#dist-algo');
  const distBtn = app.querySelector<HTMLButtonElement>('#dist-btn');
  const distResult = app.querySelector<HTMLElement>('#dist-result');
  const lextSecret = app.querySelector<HTMLInputElement>('#lext-secret');
  const lextAppend = app.querySelector<HTMLInputElement>('#lext-append');
  const lextBtn = app.querySelector<HTMLButtonElement>('#lext-btn');
  const lextResult = app.querySelector<HTMLElement>('#lext-result');

  if (
    !messageInput ||
    !hashBtn ||
    !resultsBody ||
    !themeToggle ||
    !slider ||
    !bitValue ||
    !bitLabel ||
    !liveRegion ||
    !messagePreview ||
    !analyzeBtn ||
    !grids ||
    !paddingBtn ||
    !modal ||
    !closeModalBtn ||
    !paddingContent
  ) {
    return;
  }

  const runHash = (options: { announceResult?: boolean } = {}): void => {
    const results = hashAll(messageInput.value);
    resultsBody.innerHTML = makeHashRows(results);
    if (timingHost) {
      timingHost.innerHTML = makeTimingHtml(results);
    }
    if (options.announceResult) {
      announce(
        `Hashed ${messageInput.value.length} characters. ` +
          `SHA-256 ${formatMicros(results.sha256.timeMs)}, ` +
          `SHA3-256 ${formatMicros(results.sha3.timeMs)}, ` +
          `BLAKE3 ${formatMicros(results.blake3.timeMs)}.`,
      );
    }
  };

  const updateSliderContext = (): void => {
    const max = maxBitPosition(messageInput.value);
    const hasMessage = messageInput.value.length > 0;
    slider.max = String(max);
    slider.disabled = !hasMessage;
    const clamped = Math.min(Number(slider.value), max);
    slider.value = String(clamped);
    bitValue.textContent = hasMessage ? `bit ${clamped} / ${max}` : 'no message';
    messagePreview.textContent = `Message: ${messageInput.value || '(empty)'}`;
    const summary = describeBitFlip(messageInput.value, clamped).summary;
    bitLabel.textContent = summary;
    slider.setAttribute('aria-valuetext', summary);
    if (inputStripHost) {
      renderInputStrip(inputStripHost, messageInput.value, clamped);
    }
  };

  let avalancheRendered = false;
  const runAvalanche = (options: { announceResult?: boolean } = {}): void => {
    if (messageInput.value.length === 0) {
      grids.innerHTML = '<p class="empty-state">Add a message above to analyze the avalanche effect.</p>';
      return;
    }

    avalancheRendered = true;
    const bitPosition = Number(slider.value);
    const result = avalancheAnalysis(messageInput.value, bitPosition);
    grids.innerHTML = [
      renderGrid(result.sha256, 'sha256'),
      renderGrid(result.sha3, 'sha3-256'),
      renderGrid(result.blake3, 'blake3'),
    ].join('');
    if (options.announceResult) {
      announce(
        `Flipped bit ${bitPosition}. Output bits changed: ` +
          `SHA-256 ${result.sha256.diffPercent.toFixed(1)} percent, ` +
          `SHA3-256 ${result.sha3.diffPercent.toFixed(1)} percent, ` +
          `BLAKE3 ${result.blake3.diffPercent.toFixed(1)} percent.`,
      );
    }
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        grids.querySelectorAll('.bit-cell').forEach((cell) => {
          cell.classList.add('visible');
        });
      });
    });
  };

  const showPadding = (): void => {
    const info = paddingInfo(messageInput.value);
    paddingContent.textContent = [
      `SHA-256 padded block hex:\n${info.sha256Padding}`,
      `SHA-3 rate: ${info.sha3Rate} bits`,
      `SHA-3 capacity: ${info.sha3Capacity} bits`,
    ].join('\n\n');
    modal.showModal();
  };

  hashBtn.addEventListener('click', () => runHash({ announceResult: true }));
  analyzeBtn.addEventListener('click', () => runAvalanche({ announceResult: true }));
  slider.addEventListener('input', () => {
    updateSliderContext();
    runAvalanche();
  });
  messageInput.addEventListener('input', () => {
    updateSliderContext();
    runHash();
    runAvalanche();
  });

  // Intro "what is a hash?" live one-liner.
  if (introInput && introHash) {
    const paintIntro = (): void => {
      introHash.textContent = oneLineHash(introInput.value).short;
      introHash.setAttribute('title', oneLineHash(introInput.value).full);
    };
    introInput.addEventListener('input', paintIntro);
    paintIntro();
  }

  // Avalanche distribution sweep (flip every input bit).
  if (distBtn && distAlgo && distResult) {
    distBtn.addEventListener('click', () => {
      const algo = distAlgo.value as 'sha256' | 'sha3' | 'blake3';
      renderDistribution(distResult, messageInput.value, algo);
      const d = avalancheDistribution(messageInput.value, algo);
      announce(
        `Swept ${d.percents.length} single-bit flips for ${algo}. ` +
          `Mean ${d.mean.toFixed(1)} percent output diff, clustered near 50 percent.`,
      );
    });
  }

  // Length-extension forgery demo.
  if (lextBtn && lextSecret && lextAppend && lextResult) {
    const runLext = (): void => {
      renderLengthExtension(lextResult, lextSecret.value, lextAppend.value);
    };
    lextBtn.addEventListener('click', () => {
      runLext();
      const r = lengthExtend(lextSecret.value || 'x', lextAppend.value);
      announce(
        r.verified
          ? 'Length extension succeeded: the forged SHA-256 tag validates against the reconstructed message.'
          : 'Length extension result computed.',
      );
    });
  }

  const toggle = themeToggle;

  function syncToggle(): void {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    toggle.textContent = isDark ? '\u{1F319}' : '\u{2600}\u{FE0F}';
    toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  toggle.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const next = isDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    syncToggle();
  });

  paddingBtn.addEventListener('click', showPadding);
  closeModalBtn.addEventListener('click', () => modal.close());
  modal.addEventListener('click', (event) => {
    if (event.target === modal) {
      modal.close();
    }
  });

  app.addEventListener('click', (event) => {
    void copyHash(event);
  });

  wireTabs(app);

  syncToggle();
  updateSliderContext();
  runHash();

  // Show the length-extension forgery on load so the flagship proof is visible
  // without a click; the sweep waits for a click since it is heavier.
  if (lextResult && lextSecret && lextAppend) {
    renderLengthExtension(lextResult, lextSecret.value, lextAppend.value);
  }
  if (distResult) {
    distResult.innerHTML = '<p class="empty-state">Press <strong>Run every-bit sweep</strong> to flip every input bit and plot the distribution.</p>';
  }

  // The avalanche grid is below the fold and heavy (3 x 256 animated cells).
  // Render it lazily when it scrolls into view so it stays off the initial
  // load's critical path; interacting with the controls renders it too.
  const renderAvalancheOnce = (): void => {
    if (!avalancheRendered) {
      runAvalanche();
    }
  };
  const avalancheSection = app.querySelector<HTMLElement>('#avalanche-section');
  if (typeof IntersectionObserver === 'function' && avalancheSection) {
    const observer = new IntersectionObserver(
      (entries, obs) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          obs.disconnect();
          renderAvalancheOnce();
        }
      },
      { rootMargin: '200px' },
    );
    observer.observe(avalancheSection);
  } else {
    renderAvalancheOnce();
  }
}
