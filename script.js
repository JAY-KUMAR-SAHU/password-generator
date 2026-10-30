let len = 0;
let req = [0, 0, 0, 0];
const output = document.getElementById("output");
const result = document.getElementById("result");
const errorBox = document.getElementById("error");
const copyBtn = document.getElementById("copyBtn");
const copyStatus = document.getElementById("copyStatus");
const submitBtn = document.getElementById("passwdFormSubmit");

const MAX_LEN = 128;
const fields = [
  { id: "lowerCase", name: "lowercase letters" },
  { id: "upperCase", name: "uppercase letters" },
  { id: "dig", name: "numbers" },
  { id: "sp", name: "symbols" },
];

// cryptographically secure random integer in [0, n)
function randInt(n) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % n;
}

function showError(msg, inputId) {
  errorBox.textContent = msg;
  errorBox.classList.add("show");
  if (inputId) {
    const el = document.getElementById(inputId);
    el.classList.add("invalid");
    el.focus();
  }
  return false;
}

function validate() {
  len = 0;
  req = [0, 0, 0, 0];
  errorBox.classList.remove("show");
  document
    .querySelectorAll("input.invalid")
    .forEach((el) => el.classList.remove("invalid"));

  // password length
  let curr = document.getElementById("passwdLength").value.trim();
  let n = Number(curr);
  if (curr === "" || Number.isNaN(n)) {
    return showError("Please enter a password length.", "passwdLength");
  } else if (!Number.isInteger(n)) {
    return showError("Password length must be a whole number.", "passwdLength");
  } else if (n < 8) {
    return showError(
      "Password length must be at least 8 characters.",
      "passwdLength"
    );
  } else if (n > MAX_LEN) {
    return showError(
      `Password length cannot exceed ${MAX_LEN} characters.`,
      "passwdLength"
    );
  }
  len = n;

  // minimum counts for each character type
  for (let i = 0; i < fields.length; i++) {
    curr = document.getElementById(fields[i].id).value.trim();
    n = Number(curr);
    if (curr === "" || Number.isNaN(n)) {
      return showError(
        `Please enter the minimum number of ${fields[i].name} (0 for no minimum).`,
        fields[i].id
      );
    } else if (!Number.isInteger(n) || n < 0) {
      return showError(
        `Minimum ${fields[i].name} must be a whole number, 0 or more.`,
        fields[i].id
      );
    }
    req[i] = n;
  }

  const total = req.reduce((a, b) => a + b, 0);
  if (total > len) {
    return showError(
      `The minimum character counts add up to ${total}, which exceeds the password length of ${len}. Increase the length or lower the minimums.`
    );
  }
  return true;
}

class Password {
  constructor() {
    this.pass = "";
    this.mandatory = "";
  }

  generatePassword() {
    let op = [
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "0123456789",
      "!@#$%^&*()?_",
    ];
    let minLen = req.reduce((a, b) => a + b); // sum of all req

    // mandatory part of password
    for (let i in op) {
      for (let j = 0; j < req[i]; j++) {
        this.mandatory += op[i][randInt(op[i].length)];
      }
    }

    // remaining part
    let i = 0;
    while (i < len - minLen) {
      let j = randInt(op.length);
      this.pass += op[j][randInt(op[j].length)];
      i++;
    }

    this.pass += this.mandatory;

    // Fisher-Yates shuffle
    let arr = this.pass.split("");
    for (let i = arr.length - 1; i > 0; i--) {
      let j = randInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    this.pass = arr.join("");
    return this.pass;
  }
}

// ---- time-to-crack estimate ----
const CHARSET_SIZES = [26, 26, 10, 12]; // same order as op[] in Password
const GUESSES_PER_SEC = 1e11; // fast offline attack on a GPU rig
const SECONDS_PER_YEAR = 31557600;
const UNIVERSE_AGE_YEARS = 1.38e10;

// exact number of length-L strings with at least req[i] chars of each set
function countPasswords(L, req) {
  const C = [[1n]];
  for (let n = 1; n <= L; n++) {
    C[n] = [1n];
    for (let k = 1; k < n; k++) C[n][k] = C[n - 1][k - 1] + C[n - 1][k];
    C[n][n] = 1n;
  }
  let dp = new Array(L + 1).fill(0n);
  dp[0] = 1n;
  CHARSET_SIZES.forEach((size, t) => {
    const s = BigInt(size);
    const pow = [1n];
    for (let k = 1; k <= L; k++) pow[k] = pow[k - 1] * s;
    const next = new Array(L + 1).fill(0n);
    for (let n = 0; n <= L; n++) {
      for (let k = req[t]; k <= n; k++) {
        next[n] += C[n][k] * pow[k] * dp[n - k];
      }
    }
    dp = next;
  });
  return dp[L];
}

function log2Big(x) {
  const bin = x.toString(2);
  if (bin.length <= 53) return Math.log2(Number(x));
  return bin.length - 53 + Math.log2(parseInt(bin.slice(0, 53), 2));
}

// bits of entropy, lowered slightly because the random fill picks a
// character type first, so digits/symbols are a bit more likely than letters
function entropyBits() {
  const total = CHARSET_SIZES.reduce((a, b) => a + b, 0);
  const k = CHARSET_SIZES.length;
  const fillEntropy = CHARSET_SIZES.reduce(
    (h, s) => h + Math.log2(k * s) / k,
    0
  );
  const free = len - req.reduce((a, b) => a + b, 0);
  return (
    log2Big(countPasswords(len, req)) -
    free * (Math.log2(total) - fillEntropy)
  );
}

function plural(n, word) {
  return `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;
}

function formatDuration(log10Sec) {
  if (log10Sec < 0) return "Less than a second";
  const years = 10 ** (log10Sec - Math.log10(SECONDS_PER_YEAR));
  if (years < 1) {
    const sec = 10 ** log10Sec;
    if (sec < 60) return "About " + plural(Math.round(sec), "second");
    if (sec < 3600) return "About " + plural(Math.round(sec / 60), "minute");
    if (sec < 86400) return "About " + plural(Math.round(sec / 3600), "hour");
    return "About " + plural(Math.round(sec / 86400), "day");
  }
  const big = [
    [1e12, "trillion"],
    [1e9, "billion"],
    [1e6, "million"],
  ];
  if (years >= 1e15) {
    return `About 10<sup>${Math.floor(Math.log10(years))}</sup> years`;
  }
  for (const [n, word] of big) {
    if (years >= n) return `About ${Number((years / n).toPrecision(2))} ${word} years`;
  }
  return "About " + plural(Number(years.toPrecision(2)), "year");
}

function updateStrength() {
  const bits = entropyBits();
  // on average the attacker finds it after trying half the possibilities
  const log10Sec = (bits - 1) * Math.log10(2) - Math.log10(GUESSES_PER_SEC);
  const log10Years = log10Sec - Math.log10(SECONDS_PER_YEAR);

  let level, label;
  if (log10Sec < Math.log10(86400)) [level, label] = ["weak", "Weak"];
  else if (log10Years < 2) [level, label] = ["fair", "Fair"];
  else if (log10Years < 6) [level, label] = ["strong", "Strong"];
  else [level, label] = ["very-strong", "Very strong"];

  document.getElementById("strength").dataset.level = level;
  document.getElementById("strengthLabel").textContent = label;
  document.getElementById("crackTime").innerHTML = formatDuration(log10Sec);
  document.getElementById("meterFill").style.width =
    Math.min(100, Math.max(4, (bits / 128) * 100)) + "%";
  document.getElementById("crackNote").textContent =
    (log10Years > Math.log10(UNIVERSE_AGE_YEARS)
      ? "Longer than the age of the universe. "
      : "") +
    `≈ ${Math.round(bits)} bits of entropy. Assumes a powerful offline attack at 100 billion guesses per second.`;
}

document.getElementById("passwdForm").addEventListener("submit", (e) => {
  e.preventDefault();
  if (validate()) {
    const p = new Password();
    output.textContent = p.generatePassword();
    copyStatus.textContent = "";
    copyBtn.textContent = "Copy";
    updateStrength();
    result.classList.add("show");
    submitBtn.textContent = "Regenerate password";
  }
});

// light/dark theme toggle (remembered per browser)
const themeBtns = document.querySelectorAll(".theme-btn");
const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

function currentTheme() {
  return (
    document.documentElement.dataset.theme ||
    (darkQuery.matches ? "dark" : "light")
  );
}
function syncThemeButtons() {
  const active = currentTheme();
  themeBtns.forEach((btn) =>
    btn.setAttribute(
      "aria-pressed",
      btn.dataset.themeChoice === active ? "true" : "false"
    )
  );
}
themeBtns.forEach((btn) =>
  btn.addEventListener("click", () => {
    document.documentElement.dataset.theme = btn.dataset.themeChoice;
    try {
      localStorage.setItem("theme", btn.dataset.themeChoice);
    } catch (e) {}
    syncThemeButtons();
  })
);
darkQuery.addEventListener("change", syncThemeButtons);
syncThemeButtons();

copyBtn.addEventListener("click", () => {
  // clipboard API is only available on https / localhost
  if (!navigator.clipboard) {
    copyStatus.textContent =
      "Couldn't copy automatically — select the password and copy it manually.";
    return;
  }
  navigator.clipboard
    .writeText(output.textContent)
    .then(() => {
      copyBtn.textContent = "Copied";
      copyStatus.textContent = "Password copied to clipboard.";
      setTimeout(() => {
        copyBtn.textContent = "Copy";
        copyStatus.textContent = "";
      }, 2000);
    })
    .catch(() => {
      copyStatus.textContent =
        "Couldn't copy automatically — select the password and copy it manually.";
    });
});
