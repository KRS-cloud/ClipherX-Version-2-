(() => {
  "use strict";

  const STORAGE_KEY = "cipherx_history_v1";
  const THEME_KEY = "cipherx_theme";
  const MAX_HISTORY = 20;

  const PRINTABLE_START = 32;
  const PRINTABLE_END = 126;
  const PRINTABLE_SIZE = 95;

  const XOR_KEY = 0x5a;
  const ASCII_OFFSET = 17;

  const $ = (id) => document.getElementById(id);

  const sampleMessages = [
    "Hello User B! This is a secure test message.",
    "Meet me at 8:30 PM.",
    "CipherX security test #2026",
    "Encryption should be reversible.",
    "Welcome to the Message Encryption Simulator!",
    "Protect your message with Algorithm 7.",
    "A = Alpha, B = Bravo, C = Cipher.",
    "The quick brown fox jumps over 13 lazy dogs."
  ];

  /* ============================================================
     SEEDED PERMUTATION
  ============================================================ */

  function seededRandom(seed) {
    let value = seed >>> 0;

    return () => {
      value += 0x6d2b79f5;
      let t = value;

      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);

      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function createPermutation(seed) {
    const values = Array.from(
      { length: PRINTABLE_SIZE },
      (_, index) => PRINTABLE_START + index
    );

    const random = seededRandom(seed);

    for (let i = values.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      [values[i], values[j]] = [values[j], values[i]];
    }

    return values;
  }

  const substitutionTable1 = createPermutation(101);
  const substitutionTable2 = createPermutation(202);

  const substitutionInverse1 = new Map();
  const substitutionInverse2 = new Map();

  substitutionTable1.forEach((value, index) => {
    substitutionInverse1.set(value, PRINTABLE_START + index);
  });

  substitutionTable2.forEach((value, index) => {
    substitutionInverse2.set(value, PRINTABLE_START + index);
  });

  /* ============================================================
     GENERAL HELPERS
  ============================================================ */

  function isPrintableASCII(code) {
    return code >= PRINTABLE_START && code <= PRINTABLE_END;
  }

  function assertPrintableMessage(text) {
    for (const char of text) {
      const code = char.charCodeAt(0);

      if (!isPrintableASCII(code)) {
        throw new Error(
          "This simulator supports standard printable ASCII characters only."
        );
      }
    }
  }

  function encodeEnvelope(id, payload) {
    return `CX${id}|${payload}`;
  }

  function decodeEnvelope(ciphertext, expectedId) {
    const match = /^CX(\d+)\|(.*)$/s.exec(ciphertext);

    if (!match) {
      throw new Error(
        "Invalid CipherX ciphertext. Make sure the message was encrypted by this simulator."
      );
    }

    const actualId = Number(match[1]);

    if (actualId !== expectedId) {
      throw new Error(
        `Algorithm mismatch: ciphertext was created with Algorithm ${actualId}.`
      );
    }

    return match[2];
  }

  function charShift(text, amount) {
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);

      if (!isPrintableASCII(code)) {
        throw new Error("Only printable ASCII characters are supported.");
      }

      let shifted = (code - PRINTABLE_START + amount) % PRINTABLE_SIZE;

      if (shifted < 0) {
        shifted += PRINTABLE_SIZE;
      }

      return String.fromCharCode(PRINTABLE_START + shifted);
    }).join("");
  }

  function alphabetShift(text, amount) {
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);

      if (code >= 65 && code <= 90) {
        return String.fromCharCode(65 + ((code - 65 + amount + 26) % 26));
      }

      if (code >= 97 && code <= 122) {
        return String.fromCharCode(97 + ((code - 97 + amount + 26) % 26));
      }

      return char;
    }).join("");
  }

  function escapeHTML(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  /* ============================================================
     ALGORITHM DEFINITIONS (1 - 10)
  ============================================================ */

  function encryptAlgorithm1(text) {
    assertPrintableMessage(text);
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);
      return String.fromCharCode(substitutionTable1[code - PRINTABLE_START]);
    }).join("");
  }

  function decryptAlgorithm1(text) {
    assertPrintableMessage(text);
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);
      const original = substitutionInverse1.get(code);
      if (original === undefined) {
        throw new Error("Invalid substitution ciphertext.");
      }
      return String.fromCharCode(original);
    }).join("");
  }

  function encryptAlgorithm2(text) {
    assertPrintableMessage(text);
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);
      return String.fromCharCode(substitutionTable2[code - PRINTABLE_START]);
    }).join("");
  }

  function decryptAlgorithm2(text) {
    assertPrintableMessage(text);
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);
      const original = substitutionInverse2.get(code);
      if (original === undefined) {
        throw new Error("Invalid mixed substitution ciphertext.");
      }
      return String.fromCharCode(original);
    }).join("");
  }

  function encryptAlgorithm3(text) {
    assertPrintableMessage(text);
    return alphabetShift(text, 3);
  }

  function decryptAlgorithm3(text) {
    assertPrintableMessage(text);
    return alphabetShift(text, -3);
  }

  function atbash(text) {
    return Array.from(text, (char) => {
      const code = char.charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
      if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
      return char;
    }).join("");
  }

  function encryptAlgorithm4(text) {
    assertPrintableMessage(text);
    return atbash(text);
  }

  function decryptAlgorithm4(text) {
    assertPrintableMessage(text);
    return atbash(text);
  }

  function encryptAlgorithm5(text) {
    assertPrintableMessage(text);
    return Array.from(text, (char) =>
      String(char.charCodeAt(0)).padStart(3, "0")
    ).join("-");
  }

  function decryptAlgorithm5(text) {
    if (!text) return "";
    const parts = text.split("-");
    return parts
      .map((part) => {
        if (!/^\d{3}$/.test(part)) {
          throw new Error("Invalid numeric ciphertext.");
        }
        const code = Number(part);
        if (!isPrintableASCII(code)) {
          throw new Error("Numeric ciphertext contains an invalid character.");
        }
        return String.fromCharCode(code);
      })
      .join("");
  }

  function encryptAlgorithm6(text) {
    assertPrintableMessage(text);
    return charShift(text, ASCII_OFFSET);
  }

  function decryptAlgorithm6(text) {
    assertPrintableMessage(text);
    return charShift(text, -ASCII_OFFSET);
  }

  function encryptAlgorithm7(text) {
    assertPrintableMessage(text);
    return Array.from(text)
      .map((char, index) => {
        const code = char.charCodeAt(0);
        let shifted = (code - PRINTABLE_START + (index + 1)) % PRINTABLE_SIZE;
        return String.fromCharCode(PRINTABLE_START + shifted);
      })
      .join("");
  }

  function decryptAlgorithm7(text) {
    assertPrintableMessage(text);
    return Array.from(text)
      .map((char, index) => {
        const code = char.charCodeAt(0);
        let shifted = (code - PRINTABLE_START - (index + 1)) % PRINTABLE_SIZE;
        if (shifted < 0) shifted += PRINTABLE_SIZE;
        return String.fromCharCode(PRINTABLE_START + shifted);
      })
      .join("");
  }

  function encryptAlgorithm8(text) {
    assertPrintableMessage(text);
    const chars = Array.from(text);
    for (let i = 0; i < chars.length - 1; i += 2) {
      [chars[i], chars[i + 1]] = [chars[i + 1], chars[i]];
    }
    return chars.join("");
  }

  function decryptAlgorithm8(text) {
    return encryptAlgorithm8(text);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexToBytes(hex) {
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
      throw new Error("Invalid XOR hexadecimal ciphertext.");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
  }

  function encryptAlgorithm9(text) {
    assertPrintableMessage(text);
    const bytes = new TextEncoder().encode(text);
    const transformed = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      transformed[i] = bytes[i] ^ XOR_KEY;
    }
    return bytesToHex(transformed);
  }

  function decryptAlgorithm9(text) {
    const bytes = hexToBytes(text);
    const transformed = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      transformed[i] = bytes[i] ^ XOR_KEY;
    }
    return new TextDecoder().decode(transformed);
  }

  function encryptAlgorithm10(text) {
    assertPrintableMessage(text);
    const reversed = Array.from(text).reverse().join("");
    const shifted = charShift(reversed, 3);
    return encryptAlgorithm2(shifted);
  }

  function decryptAlgorithm10(text) {
    const substituted = decryptAlgorithm2(text);
    const shiftedBack = charShift(substituted, -3);
    return Array.from(shiftedBack).reverse().join("");
  }

  /* ============================================================
     ALGORITHM REGISTRY
  ============================================================ */

  const algorithms = {
    1: {
      name: "Symbol Substitution Cipher",
      type: "Substitution",
      difficulty: "Easy",
      description: "Every printable character is replaced by a unique character from a deterministic substitution table.",
      formula: "C = S(P),  P = S⁻¹(C)",
      encrypt: encryptAlgorithm1,
      decrypt: decryptAlgorithm1
    },
    2: {
      name: "Mixed Character Substitution",
      type: "Substitution",
      difficulty: "Easy",
      description: "Uses a second independent substitution table so the same input produces a different ciphertext from Algorithm 1.",
      formula: "C = S₂(P),  P = S₂⁻¹(C)",
      encrypt: encryptAlgorithm2,
      decrypt: decryptAlgorithm2
    },
    3: {
      name: "Caesar Shift",
      type: "Shift",
      difficulty: "Easy",
      description: "Alphabetic characters are shifted by three positions while preserving uppercase and lowercase letters.",
      formula: "C = (P + 3) mod 26",
      encrypt: encryptAlgorithm3,
      decrypt: decryptAlgorithm3
    },
    4: {
      name: "Atbash / Reverse Alphabet",
      type: "Substitution",
      difficulty: "Easy",
      description: "Maps A to Z, B to Y, a to z, b to y, and so on. Non-alphabetic characters remain unchanged.",
      formula: "A ↔ Z, B ↔ Y",
      encrypt: encryptAlgorithm4,
      decrypt: decryptAlgorithm4
    },
    5: {
      name: "Numeric Character Cipher",
      type: "Encoding",
      difficulty: "Easy",
      description: "Converts every printable character into its three-digit ASCII representation.",
      formula: "C = ASCII(P)",
      encrypt: encryptAlgorithm5,
      decrypt: decryptAlgorithm5
    },
    6: {
      name: "ASCII Transformation Cipher",
      type: "Transformation",
      difficulty: "Medium",
      description: "Applies a reversible modular shift across the complete printable ASCII range.",
      formula: "C = (P + 17) mod 95",
      encrypt: encryptAlgorithm6,
      decrypt: decryptAlgorithm6
    },
    7: {
      name: "Position-Based Character Shift",
      type: "Positional",
      difficulty: "Medium",
      description: "Each character is shifted according to its one-based position in the message.",
      formula: "Cᵢ = (Pᵢ + i) mod 95",
      encrypt: encryptAlgorithm7,
      decrypt: decryptAlgorithm7
    },
    8: {
      name: "Pair Swap Cipher",
      type: "Transposition",
      difficulty: "Easy",
      description: "Characters are swapped in adjacent pairs. If the message has an odd length, the final character remains in place.",
      formula: "(A B) → (B A)",
      encrypt: encryptAlgorithm8,
      decrypt: decryptAlgorithm8
    },
    9: {
      name: "XOR-Based Character Transformation",
      type: "XOR",
      difficulty: "Medium",
      description: "UTF-8 bytes are XORed with a fixed educational key and represented as hexadecimal.",
      formula: "C = P XOR 0x5A",
      encrypt: encryptAlgorithm9,
      decrypt: decryptAlgorithm9
    },
    10: {
      name: "Multi-Step Cipher",
      type: "Multi-Step",
      difficulty: "Advanced",
      description: "Combines reversal, printable ASCII shifting, and a second substitution table into one reversible process.",
      formula: "Reverse → Shift(+3) → Substitute₂",
      encrypt: encryptAlgorithm10,
      decrypt: decryptAlgorithm10
    }
  };

  /* ============================================================
     ENVELOPE WRAPPERS
  ============================================================ */

  function encryptMessage(text, algorithmId) {
    const algorithm = algorithms[algorithmId];
    if (!algorithm) throw new Error("Invalid algorithm selected.");
    if (typeof text !== "string") throw new Error("Message must be text.");

    const payload = algorithm.encrypt(text);
    return encodeEnvelope(algorithmId, payload);
  }

  function decryptMessage(ciphertext, algorithmId) {
    const algorithm = algorithms[algorithmId];
    if (!algorithm) throw new Error("Invalid algorithm selected.");

    const payload = decodeEnvelope(ciphertext, algorithmId);
    return algorithm.decrypt(payload);
  }

  /* ============================================================
     UI HELPERS & CONTROLS
  ============================================================ */

  function selectedId(selectElement) {
    return selectElement ? Number(selectElement.value) : 1;
  }

  function fillAlgorithmSelect(selectElement) {
    if (!selectElement) return;
    selectElement.innerHTML = Object.entries(algorithms)
      .map(
        ([id, algorithm]) =>
          `<option value="${id}">Algorithm ${id} — ${escapeHTML(algorithm.name)}</option>`
      )
      .join("");
  }

  function updateCounter(textarea, counter) {
    if (!textarea || !counter) return;
    counter.textContent = `${textarea.value.length} characters`;
  }

  function updateMiniInfo(selectElement, target) {
    if (!selectElement || !target) return;
    const id = selectedId(selectElement);
    const algorithm = algorithms[id];
    if (!algorithm) return;

    target.innerHTML = `
      <strong>Algorithm ${id}: ${escapeHTML(algorithm.name)}</strong><br>
      <small>${escapeHTML(algorithm.type)} · ${escapeHTML(algorithm.difficulty)}</small>
    `;
  }

  function updateAlgorithmInfo() {
    const select = $("encryptAlgorithm");
    if (!select) return;

    const id = selectedId(select);
    const algorithm = algorithms[id];
    if (!algorithm) return;

    if ($("algorithmNumber")) $("algorithmNumber").textContent = String(id).padStart(2, "0");
    if ($("algorithmName")) $("algorithmName").textContent = algorithm.name;
    if ($("algorithmType")) $("algorithmType").textContent = `${algorithm.type} · ${algorithm.difficulty}`;
    if ($("algorithmDescription")) $("algorithmDescription").textContent = algorithm.description;
    if ($("algorithmFormula")) $("algorithmFormula").textContent = algorithm.formula;

    updateExample();
    updateMiniInfo($("encryptAlgorithm"), $("encryptMiniInfo"));
    updateMiniInfo($("decryptAlgorithm"), $("decryptMiniInfo"));
  }

  function updateExample() {
    const select = $("encryptAlgorithm");
    if (!select) return;

    const id = selectedId(select);
    const algorithm = algorithms[id];
    if (!algorithm) return;

    const exampleText = "Hello!";

    try {
      const cipher = algorithm.encrypt(exampleText);
      const recovered = algorithm.decrypt(cipher);

      if ($("demoPlain")) $("demoPlain").textContent = exampleText;
      if ($("demoCipher")) $("demoCipher").textContent = cipher;
      if ($("demoRecovered")) $("demoRecovered").textContent = recovered;
    } catch (error) {
      if ($("demoPlain")) $("demoPlain").textContent = exampleText;
      if ($("demoCipher")) $("demoCipher").textContent = "Error generating sample.";
      if ($("demoRecovered")) $("demoRecovered").textContent = error.message;
    }
  }

  function setStatus(element, text, state = "") {
    if (!element) return;
    element.textContent = text;
    element.className = `status-badge ${state}`.trim();
  }

  async function copyToClipboard(text, button) {
    if (!text) {
      showNotification("There is nothing to copy.", "error");
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      if (button) {
        const original = button.textContent;
        button.textContent = "Copied!";
        setTimeout(() => {
          button.textContent = original;
        }, 1200);
      }
      showNotification("Copied to clipboard.", "success");
    } catch {
      showNotification("Clipboard access blocked by browser.", "error");
    }
  }

  function showNotification(message, type = "normal") {
    const container = $("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`.trim();
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      setTimeout(() => toast.remove(), 250);
    }, 2800);
  }

  /* ============================================================
     LOCALSTORAGE HISTORY
  ============================================================ */

  function loadHistory() {
    try {
      const data = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      return Array.isArray(data) ? data : [];
    } catch {
      return [];
    }
  }

  function saveHistory(ciphertext, algorithmId) {
    const history = loadHistory();
    history.unshift({
      ciphertext,
      algorithmId,
      timestamp: new Date().toISOString()
    });

    localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
    renderHistory();
  }

  function renderHistory() {
    const list = $("historyList");
    if (!list) return;

    const history = loadHistory();

    if (!history.length) {
      list.innerHTML = `
        <div class="empty-state">
          <span>◌</span>
          <strong>No encryption history yet</strong>
          <p>Encrypt a message and your recent ciphertext will appear here.</p>
        </div>
      `;
      return;
    }

    list.innerHTML = history
      .map((item, index) => {
        const algorithm = algorithms[item.algorithmId];
        const preview = String(item.ciphertext).replace(/\s+/g, " ").slice(0, 80);
        const date = new Date(item.timestamp);

        return `
          <button class="history-item" type="button" data-index="${index}" title="Load this history entry">
            <span class="history-number">${String(index + 1).padStart(2, "0")}</span>
            <span class="history-cipher">
              <strong>${escapeHTML(preview)}</strong>
              <small>Algorithm ${item.algorithmId} · ${escapeHTML(algorithm?.name || "Unknown")}</small>
            </span>
            <span class="history-meta">${escapeHTML(date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))}</span>
          </button>
        `;
      })
      .join("");
  }

  function loadHistoryEntry(index) {
    const item = loadHistory()[index];
    if (!item) return;

    if ($("cipherText")) $("cipherText").value = item.ciphertext;
    if ($("decryptAlgorithm")) $("decryptAlgorithm").value = String(item.algorithmId);

    updateCounter($("cipherText"), $("cipherCount"));
    updateMiniInfo($("decryptAlgorithm"), $("decryptMiniInfo"));
    setStatus($("decryptStatus"), "Loaded");

    if ($("cipherText")) $("cipherText").focus();
    showNotification("History entry loaded.", "success");
  }

  /* ============================================================
     ACTION HANDLERS
  ============================================================ */

  function verifyEncryption() {
    const plainEl = $("plainText");
    const result = $("verifyResult");
    if (!plainEl || !result) return;

    const text = plainEl.value;
    const id = selectedId($("encryptAlgorithm"));

    if (!text) {
      result.textContent = "Enter a plaintext message first.";
      result.className = "verify-result bad";
      return;
    }

    try {
      const cipher = encryptMessage(text, id);
      const recovered = decryptMessage(cipher, id);
      const success = recovered === text;

      result.textContent = success ? "✓ Encryption verified" : "✕ Verification failed";
      result.className = `verify-result ${success ? "ok" : "bad"}`;
    } catch (error) {
      result.textContent = `✕ ${error.message}`;
      result.className = "verify-result bad";
    }
  }

  function generateTestMessage() {
    const plainEl = $("plainText");
    if (!plainEl) return;

    const message = sampleMessages[Math.floor(Math.random() * sampleMessages.length)];
    plainEl.value = message;
    updateCounter(plainEl, $("plainCount"));
    plainEl.focus();
    showNotification("Test message generated.", "success");
  }

  function encryptCurrent() {
    const plainEl = $("plainText");
    const text = plainEl ? plainEl.value : "";
    const id = selectedId($("encryptAlgorithm"));

    if (!text) {
      setStatus($("encryptStatus"), "Input required", "error");
      showNotification("Please enter a message first.", "error");
      return;
    }

    try {
      const cipher = encryptMessage(text, id);
      if ($("encryptedText")) $("encryptedText").value = cipher;
      setStatus($("encryptStatus"), "Encrypted", "success");
      saveHistory(cipher, id);
      showNotification("Message encrypted successfully.", "success");
    } catch (error) {
      setStatus($("encryptStatus"), "Failed", "error");
      showNotification(error.message || "Unable to encrypt this message.", "error");
    }
  }

  function decryptCurrent() {
    const cipherEl = $("cipherText");
    const cipher = cipherEl ? cipherEl.value.trim() : "";
    const id = selectedId($("decryptAlgorithm"));

    if (!cipher) {
      setStatus($("decryptStatus"), "Input required", "error");
      showNotification("Please paste an encrypted message.", "error");
      return;
    }

    try {
      const plain = decryptMessage(cipher, id);
      if ($("decryptedText")) $("decryptedText").value = plain;
      setStatus($("decryptStatus"), "Decrypted", "success");
      showNotification("Message decrypted successfully.", "success");
    } catch (error) {
      if ($("decryptedText")) $("decryptedText").value = "";
      const mismatch = /Algorithm mismatch/i.test(error.message);

      setStatus($("decryptStatus"), mismatch ? "Mismatch" : "Failed", mismatch ? "warn" : "error");
      showNotification(
        mismatch
          ? `${error.message} Make sure User B selected the same algorithm.`
          : "Unable to decrypt this message. Check the algorithm and ciphertext.",
        "error"
      );
    }
  }

  function syncToReceiver() {
    const encEl = $("encryptedText");
    const cipher = encEl ? encEl.value : "";

    if (!cipher) {
      showNotification("Encrypt a message before sending it to User B.", "error");
      return;
    }

    if ($("cipherText")) $("cipherText").value = cipher;
    if ($("decryptAlgorithm")) $("decryptAlgorithm").value = $("encryptAlgorithm").value;

    updateCounter($("cipherText"), $("cipherCount"));
    updateMiniInfo($("decryptAlgorithm"), $("decryptMiniInfo"));
    setStatus($("decryptStatus"), "Ready");

    if ($("cipherText")) $("cipherText").focus();
    showNotification("Encrypted message sent to User B.", "success");
  }

  function clearField(id, statusId) {
    const target = $(id);
    if (target) target.value = "";

    if (statusId) {
      setStatus($(statusId), statusId === "encryptStatus" ? "Ready" : "Waiting");
    }
  }

  function clearAll() {
    ["plainText", "encryptedText", "cipherText", "decryptedText"].forEach((id) => {
      const el = $(id);
      if (el) el.value = "";
    });

    updateCounter($("plainText"), $("plainCount"));
    updateCounter($("cipherText"), $("cipherCount"));

    setStatus($("encryptStatus"), "Ready");
    setStatus($("decryptStatus"), "Waiting");

    if ($("verifyResult")) {
      $("verifyResult").textContent = "";
      $("verifyResult").className = "verify-result";
    }

    showNotification("Workspace cleared.", "success");
  }

  /* ============================================================
     THEME MANAGEMENT
  ============================================================ */

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    const theme = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    document.documentElement.dataset.theme = theme;
    if ($("themeToggle")) $("themeToggle").textContent = theme === "light" ? "☾" : "☼";
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    localStorage.setItem(THEME_KEY, next);
    if ($("themeToggle")) $("themeToggle").textContent = next === "light" ? "☾" : "☼";
  }

  /* ============================================================
     SELF TESTS
  ============================================================ */

  function runSelfTests() {
    const cases = [
      "Hello World! 123",
      "Welcome Pankaj",
      "Meet me at 8:30 PM.",
      "Encryption @ Home #2026"
    ];

    const failures = [];

    for (let id = 1; id <= 10; id++) {
      for (const sample of cases) {
        try {
          const cipher = encryptMessage(sample, id);
          const recovered = decryptMessage(cipher, id);
          if (recovered !== sample) failures.push(`Algorithm ${id}: round-trip mismatch`);
        } catch (error) {
          failures.push(`Algorithm ${id}: ${error.message}`);
        }
      }
    }

    return failures;
  }

  /* ============================================================
     EVENT BINDINGS & INIT
  ============================================================ */

  function addSafeListener(id, event, handler) {
    const el = $(id);
    if (el) el.addEventListener(event, handler);
  }

  function bindEvents() {
    addSafeListener("plainText", "input", () => updateCounter($("plainText"), $("plainCount")));
    addSafeListener("cipherText", "input", () => updateCounter($("cipherText"), $("cipherCount")));

    addSafeListener("encryptAlgorithm", "change", () => {
      updateAlgorithmInfo();
      if ($("decryptAlgorithm")) $("decryptAlgorithm").value = $("encryptAlgorithm").value;
      updateMiniInfo($("decryptAlgorithm"), $("decryptMiniInfo"));
    });

    addSafeListener("decryptAlgorithm", "change", () => {
      updateMiniInfo($("decryptAlgorithm"), $("decryptMiniInfo"));
    });

    addSafeListener("encryptBtn", "click", encryptCurrent);
    addSafeListener("decryptBtn", "click", decryptCurrent);
    addSafeListener("verifyBtn", "click", verifyEncryption);
    addSafeListener("sendToBBtn", "click", syncToReceiver);
    addSafeListener("randomMessageBtn", "click", generateTestMessage);

    addSafeListener("heroTestBtn", "click", () => {
      generateTestMessage();
      location.hash = "workspace";
    });

    addSafeListener("copyEncryptedBtn", "click", () =>
      copyToClipboard($("encryptedText")?.value, $("copyEncryptedBtn"))
    );

    addSafeListener("copyDecryptedBtn", "click", () =>
      copyToClipboard($("decryptedText")?.value, $("copyDecryptedBtn"))
    );

    addSafeListener("clearPlainBtn", "click", () => {
      clearField("plainText", null);
      updateCounter($("plainText"), $("plainCount"));
    });

    addSafeListener("clearEncryptedBtn", "click", () =>
      clearField("encryptedText", "encryptStatus")
    );

    addSafeListener("clearDecryptedBtn", "click", () =>
      clearField("decryptedText", "decryptStatus")
    );

    addSafeListener("clearAllBtn", "click", clearAll);

    addSafeListener("clearHistoryBtn", "click", () => {
      const history = loadHistory();
      if (!history.length) {
        showNotification("History is already empty.");
        return;
      }

      if (confirm("Clear all saved encryption history?")) {
        localStorage.removeItem(STORAGE_KEY);
        renderHistory();
        showNotification("History cleared.", "success");
      }
    });

    addSafeListener("historyList", "click", (event) => {
      const item = event.target.closest("[data-index]");
      if (item) loadHistoryEntry(Number(item.dataset.index));
    });

    addSafeListener("themeToggle", "click", toggleTheme);
  }

  function init() {
    fillAlgorithmSelect($("encryptAlgorithm"));
    fillAlgorithmSelect($("decryptAlgorithm"));

    if ($("encryptAlgorithm")) $("encryptAlgorithm").value = "3";
    if ($("decryptAlgorithm")) $("decryptAlgorithm").value = "3";

    initTheme();

    updateCounter($("plainText"), $("plainCount"));
    updateCounter($("cipherText"), $("cipherCount"));

    updateAlgorithmInfo();
    renderHistory();
    bindEvents();

    const failures = runSelfTests();
    if (failures.length) {
      console.error("CipherX self-test failures:", failures);
      showNotification("A built-in cipher self-test failed. Check console.", "error");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();