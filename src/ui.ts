import { describeBitFlip, maxBitPosition } from './avalanche';
import { avalancheAnalysis, hashAll, paddingInfo, type AvalanchePerAlgorithm, type HashResults } from './hasher';

const defaultMessage = 'The quick brown fox jumps over the lazy dog';

function renderByteSpans(hex: string): string {
  const chunks = hex.match(/.{1,2}/g) ?? [];
  return chunks
    .map((chunk, index) => `<span class="byte byte-${index % 8}">${chunk}</span>`)
    .join('');
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
      <th scope="row">Time (avg µs)</th>
      <td data-label="SHA-256">${formatMicros(results.sha256.timeMs)}</td>
      <td data-label="SHA3-256">${formatMicros(results.sha3.timeMs)}</td>
      <td data-label="BLAKE3">${formatMicros(results.blake3.timeMs)}</td>
    </tr>
    <tr>
      <th scope="row">Output size</th>
      <td data-label="SHA-256">256 bits</td>
      <td data-label="SHA3-256">256 bits</td>
      <td data-label="BLAKE3">256 bits</td>
    </tr>
    <tr>
      <th scope="row">Internal state size</th>
      <td data-label="SHA-256">256-bit chaining value</td>
      <td data-label="SHA3-256">1600-bit state (1088|512)</td>
      <td data-label="BLAKE3">256-bit chaining value per node</td>
    </tr>
    <tr>
      <th scope="row">Construction</th>
      <td data-label="SHA-256">Merkle-Damgaard</td>
      <td data-label="SHA3-256">Sponge (Keccak-f[1600])</td>
      <td data-label="BLAKE3">Binary tree hash</td>
    </tr>
  `;
}

function renderGrid(data: AvalanchePerAlgorithm, id: string): string {
  const pct = data.diffPercent;
  const delta = Math.abs(pct - 50);
  const quality = delta <= 6 ? 'ideal' : delta <= 12 ? 'good' : 'off';
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
    </div>
  `;
}

function buildAppHtml(): string {
  return `
    <a href="#hash-comparison" class="skip-link">Skip to main content</a>
    <header class="topbar">
      <div>
        <span class="badge">crypto-lab portfolio demo</span>
        <h1>Hash Zoo - crypto-lab</h1>
        <p>Compare SHA-256, SHA3-256, and BLAKE3 internals in one live playground.</p>
      </div>
      <button id="theme-toggle" type="button" aria-label="Switch to light mode" title="Toggle color theme"></button>
    </header>

    <main>

    <section class="panel" id="hash-comparison">
      <h2>Section A - Hash Comparison</h2>
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
    </section>

    <section class="panel" id="avalanche-section">
      <h2>Section B - Avalanche Effect</h2>
      <p id="message-preview"></p>
      <div class="slider-row">
        <label for="bit-slider">Bit position to flip</label>
        <output id="bit-value" for="bit-slider" class="slider-value">0</output>
      </div>
      <input id="bit-slider" type="range" min="0" value="0" step="1" aria-describedby="bit-label" />
      <p id="bit-label"></p>
      <button id="analyze-btn" type="button">Analyze Avalanche</button>
      <ul class="legend" aria-label="Avalanche grid legend">
        <li><span class="legend-swatch swatch-changed" aria-hidden="true"></span> Changed bit (striped)</li>
        <li><span class="legend-swatch swatch-same" aria-hidden="true"></span> Unchanged bit (solid)</li>
        <li><span class="legend-swatch swatch-ideal" aria-hidden="true"></span> Meter mark = ideal 50%</li>
      </ul>
      <div id="avalanche-grids" class="avalanche-wrap">
        <p class="empty-state">Scroll here or press <strong>Analyze Avalanche</strong> to compute the bit-change grids.</p>
      </div>
      <p class="ideal-note">A strong hash flips roughly 50% of output bits when a single input bit changes. Each card's meter shows how close it lands to that ideal.</p>
    </section>

    <section class="panel" id="construction-section">
      <h2>Section C - Construction Comparison</h2>
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
        <p>SHA-256 uses a Davies-Meyer style compression approach over 64 rounds and fixed IV constants derived from square roots of primes. Bare Merkle-Damgaard hashes are length-extension vulnerable, while HMAC-SHA256 remains safe because the key is mixed on both inner and outer passes.</p>
      </div>
      <div class="tab-panel" role="tabpanel" id="panel-sponge" aria-labelledby="tab-sponge" data-panel="sponge">
        <p>SHA3-256 is built from Keccak-f[1600], alternating absorb and squeeze phases with rate/capacity partitioning. Its sponge structure was standardized to provide a distinct design line from SHA-2 and is resistant to length extension by construction.</p>
      </div>
      <div class="tab-panel" role="tabpanel" id="panel-tree" aria-labelledby="tab-tree" data-panel="tree">
        <p>BLAKE3 uses a Bao-compatible binary tree over 1024-byte chunks with parent-node chaining values. Tree hashing makes parallel processing natural, maps well to SIMD, and supports XOF/KDF style key derivation modes.</p>
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
