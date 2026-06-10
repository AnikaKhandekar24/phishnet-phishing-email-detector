const messageInput = document.querySelector("#messageInput");
const charCount = document.querySelector("#charCount");
const analyzeButton = document.querySelector("#analyzeButton");
const clearButton = document.querySelector("#clearButton");
const emptyState = document.querySelector("#emptyState");
const analysisResults = document.querySelector("#analysisResults");

const samples = {
  delivery: `FINAL NOTICE: Your package could not be delivered due to an unpaid shipping fee. You must act immediately to avoid return of your parcel. Pay $2.99 now at http://fedex-redelivery.support/track. Failure to respond within 24 hours will result in permanent cancellation.`,
  account: `Dear Customer, We detected unusual activity on your bank account. Your access will be suspended today unless you verify your identity immediately. Click here: https://secure-bank-login.xyz/verify and enter your password and account number.`,
  safe: `Hi Maya,\n\nHere are the notes from today's project meeting. The updated presentation is in our usual shared folder. When you have time tomorrow, could you review slides 8–12?\n\nThanks,\nDaniel`
};

const rules = {
  urgency: {
    label: "Urgent language",
    icon: "!",
    patterns: [
      /\b(act now|act immediately|immediate action|urgent|final notice|last chance|within \d+ hours?|right away|as soon as possible|expires? soon|failure to respond|avoid (?:closure|suspension|cancellation))\b/gi
    ],
    weight: 7,
    description: "Pressure or fear-based wording"
  },
  credentials: {
    label: "Sensitive request",
    icon: "⌁",
    patterns: [
      /\b(password|passcode|pin|social security|ssn|account number|credit card|bank details|verify your identity|login credentials|gift cards?|wire transfer|crypto(?:currency)?)\b/gi
      ,/\b(?:pay|send|transfer)\s+(?:\$|£|€)?\d+(?:\.\d{2})?\b|\b(?:unpaid|outstanding)\s+(?:shipping\s+)?fee\b/gi
    ],
    weight: 11,
    description: "Requests for private data or payment"
  },
  threats: {
    label: "Threats & consequences",
    icon: "×",
    patterns: [
      /\b(suspend(?:ed)?|disable(?:d)?|terminate(?:d)?|close(?:d)?|cancel(?:led|ed|lation)?|locked?|legal action|arrest|penalty|unauthorized activity|unusual activity|compromised)\b/gi
    ],
    weight: 8,
    description: "Threatening account or legal consequences"
  },
  generic: {
    label: "Impersonal greeting",
    icon: "?",
    patterns: [/\b(dear (?:customer|user|member|account holder)|valued customer|attention user)\b/gi],
    weight: 7,
    description: "Generic instead of personal wording"
  },
  errors: {
    label: "Writing quality",
    icon: "Aa",
    patterns: [
      /\b(kindly (?:do|click|send|verify)|revert back|do the needful|your account have|we has|information are|congratulation|recieve|securty|immediatly|verif(?:i|y)e)\b/gi,
      /[!?]{3,}/g
    ],
    weight: 5,
    description: "Grammar, spelling, or punctuation issues"
  }
};

const suspiciousTlds = /\.(?:xyz|top|click|support|buzz|monster|rest|gq|tk|ml|cf|work|zip)(?:[/:?#]|$)/i;
const shorteners = /\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|tiny\.cc)\b/i;
const ipAddressUrl = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i;
const urlsPattern = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;

function findMatches(text, patterns) {
  const matches = [];
  patterns.forEach((pattern) => {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      matches.push({ text: match[0], index: match.index });
    }
  });
  return matches;
}

function inspectLinks(text) {
  const links = text.match(urlsPattern) || [];
  const suspicious = links.filter((url) => {
    const cleaned = url.replace(/[),.;!?]+$/, "");
    return suspiciousTlds.test(cleaned) ||
      shorteners.test(cleaned) ||
      ipAddressUrl.test(cleaned) ||
      /@/.test(cleaned) ||
      /(?:paypa[l1]|micr[o0]soft|g[o0]{2}gle|amaz[o0]n|netfl[i1]x|faceb[o0]{2}k)[.-][a-z0-9-]+\./i.test(cleaned);
  });
  return { links, suspicious };
}

function analyzeMessage(text) {
  const findings = [];
  let score = 0;

  Object.values(rules).forEach((rule) => {
    const matches = findMatches(text, rule.patterns);
    const points = Math.min(matches.length * rule.weight, rule.weight * 3);
    score += points;
    findings.push({ ...rule, count: matches.length, matches, points });
  });

  const linkResult = inspectLinks(text);
  const linkPoints = Math.min(linkResult.suspicious.length * 18, 36);
  score += linkPoints;
  findings.splice(1, 0, {
    label: "Suspicious links",
    icon: "↗",
    description: "Odd, disguised, or risky web addresses",
    count: linkResult.suspicious.length,
    matches: linkResult.suspicious.map((link) => ({ text: link, index: text.indexOf(link) })),
    points: linkPoints
  });

  if (/\b(click here|tap here|open the link|follow this link|download attachment)\b/i.test(text)) score += 6;
  if (/\b(prize|winner|won|refund|inheritance|free money|reward)\b/i.test(text)) score += 9;
  if (text.length < 35) score = Math.min(score, 55);

  score = Math.min(Math.round(score), 100);
  return { score, findings, linkResult };
}

function riskMeta(score) {
  if (score >= 55) return {
    label: "High risk",
    color: "#e84f45",
    summary: "Multiple strong phishing signals detected.",
    advice: "Do not click links, reply, or share information. Contact the organization using a trusted website, app, or phone number."
  };
  if (score >= 35) return {
    label: "Caution",
    color: "#e89837",
    summary: "Some suspicious signals need a closer look.",
    advice: "Pause before acting. Verify the sender and open the organization’s official app or website yourself instead of using message links."
  };
  return {
    label: "Low risk",
    color: "#41a979",
    summary: score === 0 ? "No major warning signs found." : "A few weak signals were found.",
    advice: "No strong phishing pattern was detected, but stay cautious with unexpected links, attachments, and requests for private information."
  };
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function highlightedHtml(text, findings, suspiciousLinks) {
  const ranges = [];
  findings.forEach((finding) => {
    finding.matches.forEach((match) => {
      ranges.push({ start: match.index, end: match.index + match.text.length, type: "phrase" });
    });
  });
  suspiciousLinks.forEach((link) => {
    const start = text.indexOf(link);
    if (start >= 0) ranges.push({ start, end: start + link.length, type: "link" });
  });
  ranges.sort((a, b) => a.start - b.start || b.end - a.end);

  const merged = [];
  ranges.forEach((range) => {
    if (range.start < 0) return;
    const last = merged.at(-1);
    if (last && range.start < last.end) {
      if (range.end > last.end) last.end = range.end;
      if (range.type === "link") last.type = "link";
    } else {
      merged.push({ ...range });
    }
  });

  let cursor = 0;
  let html = "";
  merged.forEach((range) => {
    html += escapeHtml(text.slice(cursor, range.start));
    html += `<mark class="${range.type}">${escapeHtml(text.slice(range.start, range.end))}</mark>`;
    cursor = range.end;
  });
  return html + escapeHtml(text.slice(cursor));
}

function renderAnalysis(result, text) {
  const meta = riskMeta(result.score);
  const badge = document.querySelector("#riskBadge");
  const ring = document.querySelector("#scoreRing");

  emptyState.hidden = true;
  analysisResults.hidden = false;
  badge.textContent = meta.label;
  badge.style.color = meta.color;
  badge.style.background = `${meta.color}1f`;
  document.querySelector("#scoreValue").textContent = result.score;
  document.querySelector("#ringValue").textContent = result.score;
  document.querySelector("#scoreSummary").textContent = meta.summary;
  document.querySelector("#adviceText").textContent = meta.advice;
  ring.style.setProperty("--score", result.score);
  ring.style.setProperty("--score-color", meta.color);

  document.querySelector("#signalList").innerHTML = result.findings.map((finding) => `
    <div class="signal-item ${finding.count ? "flagged" : ""}">
      <div class="signal-icon">${finding.icon}</div>
      <div>
        <h3>${finding.label}</h3>
        <p>${finding.description}</p>
      </div>
      <span class="signal-count">${finding.count ? `${finding.count} found` : "Clear"}</span>
    </div>
  `).join("");

  document.querySelector("#highlightedMessage").innerHTML =
    highlightedHtml(text, result.findings, result.linkResult.suspicious);
}

function runAnalysis() {
  const text = messageInput.value.trim();
  if (!text) {
    messageInput.focus();
    messageInput.closest(".input-wrap").animate(
      [{ transform: "translateX(0)" }, { transform: "translateX(-5px)" }, { transform: "translateX(5px)" }, { transform: "translateX(0)" }],
      { duration: 250 }
    );
    return;
  }
  analyzeButton.textContent = "Scanning...";
  analyzeButton.disabled = true;
  setTimeout(() => {
    renderAnalysis(analyzeMessage(text), text);
    analyzeButton.innerHTML = `Analyze message <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6"/></svg>`;
    analyzeButton.disabled = false;
    if (window.innerWidth < 900) analysisResults.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 380);
}

messageInput.addEventListener("input", () => {
  charCount.textContent = `${messageInput.value.length.toLocaleString()} / 5,000`;
});

messageInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") runAnalysis();
});

analyzeButton.addEventListener("click", runAnalysis);

clearButton.addEventListener("click", () => {
  messageInput.value = "";
  charCount.textContent = "0 / 5,000";
  analysisResults.hidden = true;
  emptyState.hidden = false;
  messageInput.focus();
});

document.querySelectorAll(".sample-chip").forEach((button) => {
  button.addEventListener("click", () => {
    messageInput.value = samples[button.dataset.sample];
    messageInput.dispatchEvent(new Event("input"));
    messageInput.focus();
  });
});
