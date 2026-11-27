/**
 * वेद दिनदर्शिका - ॲडमिन डॅशबोर्ड ॲप्लिकेशन लॉजिक
 * Client-Side AES-256 GCM Encryption & Decryption Engine
 * Live GitHub Auto-Publish & FeatureFlags Management
 * Secret PIN Encrypted Vault System
 */

// १. गुप्त कूटबद्धीकरण की (CryptoManager.kt शी तंतोतंत जुळणारी 256-bit AES Key)
const AES_SECRET_PHRASE = "VedDindarshikaPanchangSecret2027";
const PIN_VAULT_SALT = "VedDindarshikaPinVaultSalt2027";
let cryptoKey = null;

// २. सक्रिय स्टेट (Active State)
let currentYear = 2026;
let currentMonth = 11;
let activeCalendarData = [];
let selectedDayData = null;
let cachedVaultBytes = null;

// दोन्ही वर्षांचा डेटा मेमरी व सेशन कॅशमध्ये ठेवणे (Auto-Cache)
const calendarDataCache = {
  2026: null,
  2027: null
};

// रिमोट व्हर्जन व जाहिरात कॉन्फिगरेशन
let activeVersionConfig = {
  version: 31,
  last_updated: "2026-11-27",
  active_years: [2026, 2027],
  enable_status_share: false,
  enable_ads: true,
  enable_banner_ads: true,
  enable_interstitial_ads: true,
  enable_native_ads: true,
  force_test_ads: false,
  interstitial_interval: 4,
  years: {
    "2026": {
      version: 11,
      calendar_file: "calendar_data_2026.enc",
      extras_file: "panchang_extras_2026.enc",
      rashi_file: "rashi_bhavishya_2026.enc",
      panchang_table_file: ""
    },
    "2027": {
      version: 12,
      calendar_file: "calendar_data_2027.enc",
      extras_file: "panchang_extras_2027.enc",
      rashi_file: "rashi_bhavishya_2027.enc",
      panchang_table_file: "panchang_data_2027.enc"
    }
  }
};

const MARATHI_MONTHS_NAMES = [
  "जानेवारी", "फेब्रुवारी", "मार्च", "एप्रिल", "मे", "जून",
  "जुलै", "ऑगस्ट", "सप्टेंबर", "ऑक्टोबर", "नोव्हेंबर", "डिसेंबर"
];

const MARATHI_DIGITS = ['०', '१', '२', '३', '४', '५', '६', '७', '८', '९'];

function toMarathiDigits(num) {
  return String(num).split('').map(c => (c >= '0' && c <= '9') ? MARATHI_DIGITS[parseInt(c)] : c).join('');
}

// ३. Base64 & Binary Utilities
function uint8ArrayToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToUint8Array(base64) {
  const binaryString = window.atob(base64.replace(/\s/g, ''));
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function utf8ToBase64(str) {
  return window.btoa(unescape(encodeURIComponent(str)));
}

function base64ToUtf8(str) {
  return decodeURIComponent(escape(window.atob(str.replace(/\s/g, ''))));
}

// ४. Web Crypto API द्वारे AES Key इनिशिअलायझेशन
async function initCryptoKey() {
  try {
    if (!window.crypto || !window.crypto.subtle) {
      console.warn("WebCrypto not available in this context");
      return;
    }
    const enc = new TextEncoder();
    const rawKey = enc.encode(AES_SECRET_PHRASE);
    cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    console.log("✓ WebCrypto AES-256 GCM Engine Ready");
  } catch (err) {
    console.warn("Crypto init error:", err);
  }
}

// ५. AES-256 GCM कॅलेंडर एन्क्रिप्शन / डिक्रिप्शन
async function encryptPayload(jsonText) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("WebCrypto सिस्टीम उपलब्ध नाही. कृपया HTTPS किंवा http://localhost द्वारे उघडा.");
  }
  if (!cryptoKey) await initCryptoKey();
  const enc = new TextEncoder();
  const data = enc.encode(jsonText);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuf = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv, tagLength: 128 },
    cryptoKey,
    data
  );

  const combined = new Uint8Array(12 + encryptedBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuf), 12);
  return combined;
}

async function decryptPayload(binaryData) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("WebCrypto सिस्टीम उपलब्ध नाही. कृपया HTTPS किंवा http://localhost द्वारे उघडा.");
  }
  if (!cryptoKey) await initCryptoKey();
  const bytes = new Uint8Array(binaryData);
  if (bytes.length < 28) throw new Error("अवैध एन्क्रिप्टेड फाईल");

  const iv = bytes.slice(0, 12);
  const cipherWithTag = bytes.slice(12);

  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv, tagLength: 128 },
    cryptoKey,
    cipherWithTag
  );

  const dec = new TextDecoder();
  return dec.decode(decryptedBuf);
}

// ६. सिक्रेट पिन व्हॉल्ट क्रिप्टोग्राफी (PBKDF2 + AES-256 GCM)
async function deriveKeyFromPin(pin) {
  const enc = new TextEncoder();
  const pinKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(PIN_VAULT_SALT),
      iterations: 100000,
      hash: "SHA-256"
    },
    pinKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptTokenWithPin(token, pin) {
  const key = await deriveKeyFromPin(pin);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipher = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(token)
  );
  const vault = new Uint8Array(12 + cipher.byteLength);
  vault.set(iv, 0);
  vault.set(new Uint8Array(cipher), 12);
  return vault;
}

async function decryptTokenWithPin(vaultBytes, pin) {
  const key = await deriveKeyFromPin(pin);
  const iv = vaultBytes.slice(0, 12);
  const cipher = vaultBytes.slice(12);
  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    cipher
  );
  const dec = new TextDecoder();
  return dec.decode(decryptedBuf);
}

// ७. सूचना दाखवणे (Alert Helper)
function showAlert(message, type = "green") {
  const alertEl = document.getElementById("statusAlert");
  const textEl = document.getElementById("statusAlertText");
  if (!alertEl || !textEl) return;
  textEl.textContent = message;
  alertEl.className = "p-3.5 rounded-xl text-sm font-medium flex items-center justify-between shadow-sm transition " +
    (type === "green" ? "bg-emerald-50 text-emerald-800 border border-emerald-200" :
     type === "blue" ? "bg-blue-50 text-blue-800 border border-blue-200" :
     "bg-red-50 text-red-800 border border-red-200");
  alertEl.classList.remove("hidden");
  setTimeout(() => { alertEl.classList.add("hidden"); }, 6000);
}

// ८. GitHub API इंटिग्रेशन
function getGitHubCredentials() {
  const token = sessionStorage.getItem("ved_github_token") || "";
  const repo = localStorage.getItem("ved_github_repo") || "rushikesh143143/VedDindarshika";
  const branch = localStorage.getItem("ved_github_branch") || "main";
  return { token, repo, branch };
}

function updateGitHubConnectionStatus() {
  const { token, repo } = getGitHubCredentials();
  const badge = document.getElementById("githubStatusBadge");
  const tokenStatusText = document.getElementById("tokenStatusText");
  const repoLabel = document.getElementById("repoNameLabel");
  const vaultStatus = document.getElementById("vaultStatusBadge");

  if (repoLabel) repoLabel.textContent = `Repo: ${repo}`;

  if (token && token.trim().startsWith("ghp_")) {
    if (badge) {
      badge.className = "flex items-center gap-1 px-2.5 py-0.5 rounded-full font-bold bg-emerald-100 text-emerald-800 border border-emerald-300";
      badge.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> GitHub: कनेक्टेड`;
    }
    if (tokenStatusText) {
      tokenStatusText.className = "text-[11px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800";
      tokenStatusText.textContent = "✓ सुरक्षित सेव्ह आहे";
    }
    if (vaultStatus) {
      vaultStatus.className = "text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800";
      vaultStatus.textContent = "✓ व्हॉल्ट सक्रिय";
    }
  } else {
    if (badge) {
      badge.className = "flex items-center gap-1 px-2.5 py-0.5 rounded-full font-bold bg-amber-100 text-amber-800 border border-amber-300";
      badge.innerHTML = `<span class="w-2 h-2 rounded-full bg-amber-500"></span> 🔐 पिन आवश्यक`;
    }
    if (tokenStatusText) {
      tokenStatusText.className = "text-[11px] font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800";
      tokenStatusText.textContent = "टोकन आवश्यक";
    }
    if (vaultStatus) {
      vaultStatus.className = "text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800";
      vaultStatus.textContent = "पिन आवश्यक";
    }
  }
}

const LIVE_DATA_REPO = "rushikesh143143/VedDindarshikaData";
const SOURCE_CODE_REPO = "rushikesh143143/VedDindarshika";

async function fetchGitHubFileFromRepo(repo, filePath, branch = "main") {
  const { token } = getGitHubCredentials();
  const headers = { "Accept": "application/vnd.github.v3+json" };
  if (token) headers["Authorization"] = `Bearer ${token.trim()}`;

  const res = await fetch(`https://api.github.com/repos/${repo}/contents/${filePath}?ref=${branch}&t=${Date.now()}`, {
    headers: headers
  });

  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`GitHub API Error (${repo}/${filePath} - ${res.status}): ${await res.text()}`);
  }
  return await res.json();
}

async function pushGitHubFileToRepo(repo, filePath, contentBase64, commitMessage, branch = "main") {
  const { token } = getGitHubCredentials();
  if (!token) throw new Error("GitHub Token आढळला नाही! कृपया 🔐 सिक्रेट पिन टाकून अनलॉक करा.");

  const existingFile = await fetchGitHubFileFromRepo(repo, filePath, branch).catch(() => null);
  const existingSha = existingFile ? existingFile.sha : null;

  const body = {
    message: commitMessage,
    content: contentBase64,
    branch: branch
  };
  if (existingSha) body.sha = existingSha;

  const res = await fetch(`https://api.github.com/repos/${repo}/contents/${filePath}`, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${token.trim()}`,
      "Accept": "application/vnd.github.v3+json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub Commit Error (${repo}/${filePath} - ${res.status}): ${errText}`);
  }
  return await res.json();
}

async function fetchGitHubFile(filePath) {
  const { repo, branch } = getGitHubCredentials();
  return await fetchGitHubFileFromRepo(repo, filePath, branch);
}

async function pushGitHubFile(filePath, contentBase64, commitMessage, existingSha = null) {
  const { repo, branch } = getGitHubCredentials();
  return await pushGitHubFileToRepo(repo, filePath, contentBase64, commitMessage, branch);
}

// ९. जाहिरात व व्हर्जन UI
function updateVersionAndFlagsUI() {
  document.getElementById("lblGlobalVersion").textContent = toMarathiDigits(activeVersionConfig.version || 31);
  if (activeVersionConfig.years && activeVersionConfig.years["2026"]) {
    document.getElementById("lbl2026Version").textContent = toMarathiDigits(activeVersionConfig.years["2026"].version || 11);
  }
  if (activeVersionConfig.years && activeVersionConfig.years["2027"]) {
    document.getElementById("lbl2027Version").textContent = toMarathiDigits(activeVersionConfig.years["2027"].version || 12);
  }

  document.getElementById("cfgEnableAds").checked = (activeVersionConfig.enable_ads !== false);
  document.getElementById("cfgEnableNativeAds").checked = (activeVersionConfig.enable_native_ads !== false);
  document.getElementById("cfgEnableBanner").checked = (activeVersionConfig.enable_banner_ads !== false);
  document.getElementById("cfgEnableInterstitial").checked = (activeVersionConfig.enable_interstitial_ads !== false);
  document.getElementById("cfgInterstitialInterval").value = activeVersionConfig.interstitial_interval || 4;
  document.getElementById("cfgForceTestAds").checked = !!activeVersionConfig.force_test_ads;
  document.getElementById("cfgEnableStatusShare").checked = !!activeVersionConfig.enable_status_share;
}

// १०. कॅलेंडर डेटा व व्हर्जन लोडिंग आणि कॅशिंग (२०२६ व २०२७ दोन्ही वर्ष ऑटो-लोड)
async function loadCalendarDataForYear(year, preferGitHub = false) {
  // १. आधी इन-मेमरी कॅश तपासा
  if (!preferGitHub && calendarDataCache[year] && Array.isArray(calendarDataCache[year]) && calendarDataCache[year].length > 0) {
    return calendarDataCache[year];
  }

  // २. draft किंवा sessionStorage तपासा (रिफ्रेश, लॉगआउट किंवा १ तासाने परत आल्यावरही बदल टिकून राहण्यासाठी)
  if (!preferGitHub) {
    try {
      const draft = localStorage.getItem(`ved_draft_cal_${year}`);
      if (draft && getHasUnsavedChanges()) {
        const parsedDraft = JSON.parse(draft);
        if (Array.isArray(parsedDraft) && parsedDraft.length > 0) {
          calendarDataCache[year] = parsedDraft;
          return parsedDraft;
        }
      }
      const stored = sessionStorage.getItem(`ved_cal_${year}`);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          calendarDataCache[year] = parsed;
          return parsed;
        }
      }
    } catch (_) {}
  }

  // ३. जर GitHub टोकन उपलब्ध असेल आणि preferGitHub असेल तर थेट GitHub API वरून आणा
  const { token } = getGitHubCredentials();
  if (preferGitHub && token && token.trim().startsWith("ghp_")) {
    try {
      let calFile = await fetchGitHubFileFromRepo(LIVE_DATA_REPO, `calendar_data_${year}.enc`).catch(() => null);
      if (!calFile) {
        calFile = await fetchGitHubFile(`data/calendar_data_${year}.enc`).catch(() => null);
      }
      if (calFile && calFile.content) {
        const encBytes = base64ToUint8Array(calFile.content);
        const decJson = await decryptPayload(encBytes);
        const data = JSON.parse(decJson);
        calendarDataCache[year] = data;
        try { sessionStorage.setItem(`ved_cal_${year}`, JSON.stringify(data)); } catch (_) {}
        return data;
      }
    } catch (e) {
      console.warn(`GitHub वरून ${year} चा डेटा लोड करताना अडचण:`, e);
    }
  }

  // ४. स्थानिक data/ किंवा क्लाउडफ्लेअर वरून तात्काळ लोड करा
  try {
    let res = await fetch(`data/calendar_data_${year}.enc?t=${Date.now()}`);
    if (!res.ok) {
      res = await fetch(`calendar_data_${year}.enc?t=${Date.now()}`);
    }
    if (res.ok) {
      const buf = await res.arrayBuffer();
      const encBytes = new Uint8Array(buf);
      const decJson = await decryptPayload(encBytes);
      const data = JSON.parse(decJson);
      calendarDataCache[year] = data;
      try { sessionStorage.setItem(`ved_cal_${year}`, JSON.stringify(data)); } catch (_) {}
      return data;
    }
  } catch (e) {
    console.warn(`स्थानिक फाईलवरून ${year} लोड करताना अडचण:`, e);
  }

  // ५. बॅकअप सॅम्पल डेटा
  const fallback = generateSampleDaysForYear(year);
  calendarDataCache[year] = fallback;
  return fallback;
}

async function loadVersionConfig(preferGitHub = false) {
  const { token } = getGitHubCredentials();
  if (preferGitHub && token && token.trim().startsWith("ghp_")) {
    try {
      let verFile = await fetchGitHubFileFromRepo(LIVE_DATA_REPO, "version.json").catch(() => null);
      if (!verFile) {
        verFile = await fetchGitHubFile("data/version.json").catch(() => null);
      }
      if (verFile && verFile.content) {
        const verText = base64ToUtf8(verFile.content);
        activeVersionConfig = JSON.parse(verText);
        updateVersionAndFlagsUI();
        try { sessionStorage.setItem("ved_version_config", JSON.stringify(activeVersionConfig)); } catch (_) {}
        return;
      }
    } catch (_) {}
  }

  // sessionStorage तपासा
  try {
    const cachedVer = sessionStorage.getItem("ved_version_config");
    if (cachedVer) {
      activeVersionConfig = JSON.parse(cachedVer);
      updateVersionAndFlagsUI();
      return;
    }
  } catch (_) {}

  // स्थानिक किंवा क्लाउडफ्लेअर वरून लोड करा
  try {
    let res = await fetch(`data/version.json?t=${Date.now()}`);
    if (!res.ok) {
      res = await fetch(`version.json?t=${Date.now()}`);
    }
    if (res.ok) {
      activeVersionConfig = await res.json();
      updateVersionAndFlagsUI();
      try { sessionStorage.setItem("ved_version_config", JSON.stringify(activeVersionConfig)); } catch (_) {}
    }
  } catch (_) {}
}

async function loadBothYears(preferGitHub = false) {
  try {
    await loadVersionConfig(preferGitHub);

    // एकाच वेळी २०२६ आणि २०२७ चे खरेखुरे डेटा समांतर (Parallel) लोड व डिक्रिप्ट करणे
    const [data2026, data2027] = await Promise.all([
      loadCalendarDataForYear(2026, preferGitHub),
      loadCalendarDataForYear(2027, preferGitHub)
    ]);

    calendarDataCache[2026] = data2026;
    calendarDataCache[2027] = data2027;

    activeCalendarData = calendarDataCache[currentYear] || (currentYear === 2026 ? data2026 : data2027);
    renderCalendarGrid();
    console.log(`✓ दोन्ही वर्षांचा डेटा यशस्वी लोड झाला: २०२६ (${data2026.length} दिवस), २०२७ (${data2027.length} दिवस)`);
  } catch (err) {
    console.error("वर्ष लोड त्रुटी:", err);
  }
}

// बदल ट्रॅकिंग व पब्लिश बटन व्यवस्थापन (Change Tracking & Publish Button State)
function getHasUnsavedChanges() {
  try {
    return localStorage.getItem("ved_has_unsaved_changes") === "true";
  } catch (_) {
    return false;
  }
}

function setHasUnsavedChanges(hasChanges) {
  try {
    if (hasChanges) {
      localStorage.setItem("ved_has_unsaved_changes", "true");
    } else {
      localStorage.removeItem("ved_has_unsaved_changes");
    }
  } catch (_) {}
  updatePublishButtonState();
}

function updatePublishButtonState() {
  const btn = document.getElementById("btnPublishGitHub");
  const badge = document.getElementById("publishBadge");
  if (!btn) return;

  const hasChanges = getHasUnsavedChanges();
  if (hasChanges) {
    btn.disabled = false;
    btn.className = "bg-emerald-500 hover:bg-emerald-600 text-white text-xs sm:text-sm font-bold px-3.5 py-2 rounded-lg transition flex items-center gap-1.5 shadow-md border border-emerald-400 cursor-pointer";
    btn.title = "नवीन बदल थेट GitHub वर पब्लिश करण्यासाठी क्लिक करा";
    if (badge) badge.classList.remove("hidden");
  } else {
    btn.disabled = true;
    btn.className = "opacity-50 cursor-not-allowed bg-slate-600 text-slate-300 text-xs sm:text-sm font-bold px-3.5 py-2 rounded-lg transition flex items-center gap-1.5 shadow border border-slate-500";
    btn.title = "कोणतेही बदल शिल्लक नाहीत (सर्व डेटा आधीच पब्लिश झाला आहे)";
    if (badge) badge.classList.add("hidden");
  }
}

async function loadLiveDataFromGitHub() {
  if (getHasUnsavedChanges()) {
    const discard = confirm("⚠️ लक्ष द्या!\n\nतुमचे काही बदल अजून पब्लिश केलेले नाहीत!\nजर तुम्ही आता GitHub वरून नवीन डेटा लोड केला, तर तुमचे न पब्लिश केलेले बदल निघून जातील.\n\nतुम्हाला खरंच बदल रद्द करून GitHub चा डेटा लोड करायचा आहे का?");
    if (!discard) return;
    setHasUnsavedChanges(false);
  }

  try {
    showAlert("GitHub वरून २०२६ व २०२७ चे अपडेट्स लोड करत आहे...", "blue");
    await loadBothYears(true);
    setHasUnsavedChanges(false);
    showAlert(`✓ २०२६ (${calendarDataCache[2026]?.length || 0} दिवस) व २०२७ (${calendarDataCache[2027]?.length || 0} दिवस) चे खरेखुरे डेटा लोड झाले!`, "green");
  } catch (err) {
    console.warn("GitHub live load error:", err);
    showAlert("GitHub लोड त्रुटी: " + err.message, "red");
  }
}

// ११. थेट GitHub वर One-Click Publish (AES-256 Encrypt + Version Auto-Increment)
async function publishToGitHubLive() {
  const { token, repo } = getGitHubCredentials();
  if (!token || !token.trim().startsWith("ghp_")) {
    document.getElementById("pinLockModal").classList.remove("hidden");
    showAlert("कृपया आधी 🔐 सिक्रेट पिन टाकून अनलॉक करा!", "red");
    return;
  }

  const confirmMsg = `तुम्हाला वर्ष ${toMarathiDigits(currentYear)} चे बदल थेट ॲपमध्ये लाईव्ह पब्लिश करायचे आहेत का?\n\n• डेटा आपोआप AES-256 GCM ने एन्क्रिप्ट होईल.\n• version.json व्हर्जन आपोआप +१ ने वाढेल.`;
  if (!confirm(confirmMsg)) return;

  const modal = document.getElementById("publishProgressModal");
  modal.classList.remove("hidden");

  const titleEl = document.getElementById("publishModalTitle");
  const statusEl = document.getElementById("publishModalStatus");
  const footerEl = document.getElementById("publishModalFooter");
  const stepEnc = document.getElementById("stepEncrypt");
  const stepPushCal = document.getElementById("stepPushCalendar");
  const stepVer = document.getElementById("stepUpdateVersion");
  const stepFin = document.getElementById("stepFinalize");

  titleEl.textContent = "थेट GitHub वर पब्लिश करत आहे...";
  statusEl.textContent = "कृपया थांबा, डेटा एन्क्रिप्ट करून पाठवला जात आहे...";
  footerEl.classList.add("hidden");

  const setStepActive = (el, text) => {
    el.className = "flex items-center gap-2 text-blue-600 font-bold";
    el.firstElementChild.className = "w-2 h-2 rounded-full bg-blue-500 animate-ping";
    if (text) statusEl.textContent = text;
  };
  const setStepDone = (el) => {
    el.className = "flex items-center gap-2 text-emerald-600 font-bold";
    el.firstElementChild.className = "w-2 h-2 rounded-full bg-emerald-500";
  };

  try {
    // स्टेप १: कूटबद्धीकरण
    setStepActive(stepEnc, "कॅलेंडर डेटा AES-256 GCM ने कूटबद्ध करत आहे...");
    const jsonStr = JSON.stringify(activeCalendarData, null, 2);
    const encryptedBytes = await encryptPayload(jsonStr);
    const encryptedBase64 = uint8ArrayToBase64(encryptedBytes);
    setStepDone(stepEnc);

    // स्टेप २: .enc पुश (Play Store ॲपचा थेट सर्व्हर VedDindarshikaData + बॅकअप रिपो)
    setStepActive(stepPushCal, `थेट Play Store ॲप सर्व्हरवर calendar_data_${currentYear}.enc पुश करत आहे...`);

    // १. Live Data Repo (Play Store ॲप थेट येथून डाऊनलोड करतो)
    await pushGitHubFileToRepo(
      LIVE_DATA_REPO,
      `calendar_data_${currentYear}.enc`,
      encryptedBase64,
      `Update calendar_data_${currentYear}.enc via Admin Dashboard`
    );

    // २. Source Code Repo (बॅकअप)
    try {
      await pushGitHubFileToRepo(
        SOURCE_CODE_REPO,
        `data/calendar_data_${currentYear}.enc`,
        encryptedBase64,
        `Update calendar_data_${currentYear}.enc via Admin Dashboard`
      );
    } catch (_) {}
    setStepDone(stepPushCal);

    // स्टेप ३: version.json चे व्हर्जन +१ करणे
    setStepActive(stepVer, "version.json ऑटो-इन्क्रीमेंट करून CDN कॅश त्वरित पर्ज करत आहे...");

    // Live Data Repo वरून सर्वात ताजे व्हर्जन तपासा
    const verDataFile = await fetchGitHubFileFromRepo(LIVE_DATA_REPO, "version.json").catch(() => null);
    if (verDataFile && verDataFile.content) {
      try {
        activeVersionConfig = JSON.parse(base64ToUtf8(verDataFile.content));
      } catch (_) {}
    }

    activeVersionConfig.version = (activeVersionConfig.version || 31) + 1;

    const yrKey = String(currentYear);
    if (!activeVersionConfig.years) activeVersionConfig.years = {};
    if (!activeVersionConfig.years[yrKey]) {
      activeVersionConfig.years[yrKey] = {
        version: 1,
        calendar_file: `calendar_data_${yrKey}.enc`,
        extras_file: `panchang_extras_${yrKey}.enc`,
        rashi_file: `rashi_bhavishya_${yrKey}.enc`,
        panchang_table_file: yrKey === "2027" ? "panchang_data_2027.enc" : ""
      };
    }
    activeVersionConfig.years[yrKey].version = (activeVersionConfig.years[yrKey].version || 10) + 1;

    const today = new Date();
    activeVersionConfig.last_updated = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;

    activeVersionConfig.enable_ads = document.getElementById("cfgEnableAds").checked;
    activeVersionConfig.enable_native_ads = document.getElementById("cfgEnableNativeAds").checked;
    activeVersionConfig.enable_banner_ads = document.getElementById("cfgEnableBanner").checked;
    activeVersionConfig.enable_interstitial_ads = document.getElementById("cfgEnableInterstitial").checked;
    activeVersionConfig.interstitial_interval = parseInt(document.getElementById("cfgInterstitialInterval").value, 10) || 4;
    activeVersionConfig.force_test_ads = document.getElementById("cfgForceTestAds").checked;
    activeVersionConfig.enable_status_share = document.getElementById("cfgEnableStatusShare").checked;

    const newVersionJsonText = JSON.stringify(activeVersionConfig, null, 2);
    const newVersionJsonBase64 = utf8ToBase64(newVersionJsonText);

    // १. Live Data Repo वर नवीन version.json पुश करा
    await pushGitHubFileToRepo(
      LIVE_DATA_REPO,
      "version.json",
      newVersionJsonBase64,
      `Auto-increment version to ${activeVersionConfig.version} via Admin Dashboard`
    );

    // २. Source Code Repo वर बॅकअप
    try {
      await pushGitHubFileToRepo(
        SOURCE_CODE_REPO,
        "data/version.json",
        newVersionJsonBase64,
        `Auto-increment version to ${activeVersionConfig.version} via Admin Dashboard`
      );
    } catch (_) {}

    // ३. jsDelivr CDN Cache Purge (तातडीने कॅश क्लिअर करण्यासाठी अचूक URLs)
    try {
      const purgeUrls = [
        `https://purge.jsdelivr.net/gh/${LIVE_DATA_REPO}@main/version.json`,
        `https://purge.jsdelivr.net/gh/${LIVE_DATA_REPO}@main/calendar_data_2026.enc`,
        `https://purge.jsdelivr.net/gh/${LIVE_DATA_REPO}@main/calendar_data_2027.enc`
      ];
      await Promise.allSettled(purgeUrls.map(u => fetch(u, { method: "GET" })));
    } catch (_) {}

    setStepDone(stepVer);

    // स्टेप ४: अंतिम रेंडर व कॅश अपडेट
    setStepDone(stepFin);
    calendarDataCache[currentYear] = activeCalendarData;
    try {
      sessionStorage.setItem(`ved_cal_${currentYear}`, JSON.stringify(activeCalendarData));
      sessionStorage.setItem("ved_version_config", JSON.stringify(activeVersionConfig));
      localStorage.removeItem(`ved_draft_cal_${currentYear}`);
    } catch (_) {}
    setHasUnsavedChanges(false);
    updateVersionAndFlagsUI();

    titleEl.textContent = "🎉 यशस्वीरित्या लाईव्ह पब्लिश झाले!";
    statusEl.innerHTML = `व्हर्जन नंबर आता <strong>${toMarathiDigits(activeVersionConfig.version)}</strong> झाला आहे.<br>सर्व युझर्सच्या मोबाईलमध्ये बदल काही क्षणांत आपोआप उपलब्ध होतील!`;
    footerEl.classList.remove("hidden");
    showAlert(`✓ व्हर्जन ${toMarathiDigits(activeVersionConfig.version)} थेट GitHub वर पब्लिश झाले!`, "green");

  } catch (err) {
    console.error("Publish error:", err);
    titleEl.textContent = "पब्लिश करताना त्रुटी आली";
    statusEl.textContent = err.message;
    footerEl.classList.remove("hidden");
    showAlert("पब्लिश त्रुटी: " + err.message, "red");
  }
}

// १२. व्हॉल्ट निर्मिती (Create Vault with Secret PIN)
async function handleCreateVaultWithPin() {
  const tokenInput = document.getElementById("inputGitHubToken").value.trim() || sessionStorage.getItem("ved_github_token");
  if (!tokenInput || !tokenInput.startsWith("ghp_")) {
    showAlert("कृपया आधी तुमचा GitHub Token (ghp_...) टाका!", "red");
    return;
  }

  const pinInput = document.getElementById("inputVaultPin")?.value.trim();
  if (!pinInput || pinInput.length < 4) {
    showAlert("कृपया किमान ४ अंकी सिक्रेट पिन टाका!", "red");
    return;
  }

  try {
    showAlert("सिक्रेट पिनने सुरक्षित व्हॉल्ट तयार करत आहे...", "blue");
    const vaultBytes = await encryptTokenWithPin(tokenInput, pinInput);
    cachedVaultBytes = vaultBytes;

    // Push admin_vault.enc to GitHub directly via API
    const vaultBase64 = uint8ArrayToBase64(vaultBytes);
    const existingVault = await fetchGitHubFile("dashboard/admin_vault.enc").catch(() => null);
    const existingSha = existingVault ? existingVault.sha : null;

    await pushGitHubFile(
      "dashboard/admin_vault.enc",
      vaultBase64,
      "Update encrypted admin vault",
      existingSha
    );

    // Also push to Live Data Repo (Cloudflare Pages)
    try {
      const existingLiveVault = await fetchGitHubFileFromRepo(LIVE_DATA_REPO, "admin_vault.enc").catch(() => null);
      await pushGitHubFileToRepo(
        LIVE_DATA_REPO,
        "admin_vault.enc",
        vaultBase64,
        "Update encrypted admin vault",
        "main",
        existingLiveVault ? existingLiveVault.sha : null
      );
    } catch (_) {}

    // Trigger local download as backup
    const blob = new Blob([vaultBytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "admin_vault.enc";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showAlert("✓ सिक्रेट व्हॉल्ट यशस्वीरित्या तयार होऊन GitHub वर सेव्ह झाला!", "green");
    updateGitHubConnectionStatus();

  } catch (err) {
    console.error("Vault creation error:", err);
    showAlert("व्हॉल्ट तयार करताना त्रुटी: " + err.message, "red");
  }
}

// १३. पिन द्वारे अनलॉक करणे (Unlock with PIN)
async function handleUnlockWithPin() {
  const pinInput = document.getElementById("inputPinCode").value.trim();
  const errorMsg = document.getElementById("pinErrorMsg");
  errorMsg.classList.add("hidden");

  if (!pinInput) {
    errorMsg.textContent = "कृपया पिन टाका!";
    errorMsg.classList.remove("hidden");
    return;
  }

  try {
    let vaultBytes = cachedVaultBytes;

    // Fetch admin_vault.enc if not in memory
    if (!vaultBytes) {
      try {
        const localRes = await fetch(`admin_vault.enc?t=${Date.now()}`);
        if (localRes.ok) {
          const buf = await localRes.arrayBuffer();
          vaultBytes = new Uint8Array(buf);
          cachedVaultBytes = vaultBytes;
        }
      } catch (_) {}
    }

    if (!vaultBytes) {
      errorMsg.textContent = "व्हॉल्ट फाईल आढळली नाही! आधी ⚙️ सेटिंग्जमध्ये टोकन सेव्ह करा.";
      errorMsg.classList.remove("hidden");
      return;
    }

    const decryptedToken = await decryptTokenWithPin(vaultBytes, pinInput);
    if (decryptedToken && decryptedToken.startsWith("ghp_")) {
      sessionStorage.setItem("ved_github_token", decryptedToken);
      sessionStorage.setItem("ved_admin_unlocked", "true");
      localStorage.removeItem("ved_github_token");
      document.getElementById("pinLockModal").classList.add("hidden");
      updateGitHubConnectionStatus();
      updatePublishButtonState();
      ensureJsdelivrWebhook().catch(() => {});
      if (!getHasUnsavedChanges()) {
        loadLiveDataFromGitHub();
        showAlert("✓ ॲडमिन प्रवेश यशस्वी!", "green");
      } else {
        showAlert("✓ ॲडमिन प्रवेश यशस्वी! (तुमचे न पब्लिश केलेले बदल सुरक्षित आहेत)", "amber");
      }
    } else {
      throw new Error("Invalid token decrypted");
    }

  } catch (err) {
    console.error("PIN unlock error:", err);
    errorMsg.textContent = "❌ चुकीचा पिन! कृपया पुन्हा प्रयत्न करा.";
    errorMsg.classList.remove("hidden");
    document.getElementById("inputPinCode").value = "";
    document.getElementById("inputPinCode").focus();
  }
}

// १३. jsDelivr Webhook स्वयंचलित कॉन्फिगरेशन (Instant CDN sync on every push)
async function ensureJsdelivrWebhook() {
  const { token } = getGitHubCredentials();
  if (!token || !token.trim().startsWith("ghp_")) return;

  try {
    const res = await fetch(`https://api.github.com/repos/${LIVE_DATA_REPO}/hooks`, {
      headers: {
        "Authorization": `Bearer ${token.trim()}`,
        "Accept": "application/vnd.github.v3+json"
      }
    });
    if (!res.ok) return;
    const hooks = await res.json();
    const hasJsdelivr = Array.isArray(hooks) && hooks.some(h => h.config && h.config.url && h.config.url.includes("purge.jsdelivr.net"));
    if (!hasJsdelivr) {
      await fetch(`https://api.github.com/repos/${LIVE_DATA_REPO}/hooks`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token.trim()}`,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          name: "web",
          active: true,
          events: ["push"],
          config: {
            url: "https://purge.jsdelivr.net/",
            content_type: "json",
            insecure_ssl: "0"
          }
        })
      });
      console.log("✓ jsDelivr webhook created on GitHub!");
    }
  } catch (e) {
    console.warn("Webhook check failed:", e);
  }
}

// १४. कॅलेंडर रेंडरिंग व मोडल
function generateSampleDaysForMonth(year, month) {
  const daysInMonth = new Date(year, month, 0).getDate();
  const days = [];
  const dayNames = ["रविवार", "सोमवार", "मंगळवार", "बुधवार", "गुरुवार", "शुक्रवार", "शनिवार"];

  for (let d = 1; d <= daysInMonth; d++) {
    const dt = new Date(year, month - 1, d);
    const dayOfWeekIdx = dt.getDay() === 0 ? 1 : dt.getDay() + 1;
    const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    let isSunday = (dayOfWeekIdx === 1);

    let f1 = "", f2 = "", isHol = isSunday, isShubh = false, isEkad = false, isSank = false, isPour = false, isAmav = false;

    if (year === 2026 && month === 11) {
      if (d === 5) { f1 = "वसुबारस"; f2 = "रमा एकादशी"; isEkad = true; isShubh = true; }
      else if (d === 6) { f1 = "धनत्रयोदशी"; isShubh = true; isEkad = true; }
      else if (d === 7) { f1 = "नरक चतुर्दशी"; isShubh = true; }
      else if (d === 8) { f1 = "लक्ष्मीपूजन (दिवाळी)"; isHol = true; isAmav = true; isShubh = true; }
      else if (d === 9) { f1 = "बलिप्रतिपदा (पाडवा)"; isHol = true; isShubh = true; }
      else if (d === 10) { f1 = "भाऊबीज"; isHol = true; isShubh = true; }
      else if (d === 14) { f1 = "विनायक चतुर्थी"; isAmav = true; }
      else if (d === 20) { f1 = "प्रबोधिनी एकादशी"; isEkad = true; isShubh = true; }
      else if (d === 21) { f1 = "तुळशी विवाह प्रारंभ"; isShubh = true; }
      else if (d === 24) { f1 = "त्रिपुरारी पौर्णिमा"; isPour = true; }
      else if (d === 27) { f1 = "संकष्ट चतुर्थी"; isSank = true; }
    } else {
      if (d === 15) { f1 = "संकष्ट चतुर्थी"; isSank = true; }
      if (d === 11 || d === 26) { f1 = "एकादशी"; isEkad = true; isShubh = true; }
    }

    days.push({
      date: dateStr,
      day: d,
      month: month,
      year: year,
      dayOfWeek: dayNames[dt.getDay()],
      dayOfWeekIndex: dayOfWeekIdx,
      isHoliday: isHol,
      isShubhDiwas: isShubh,
      marathiMonth: (month === 11) ? (d <= 8 ? "आश्विन" : "कार्तिक") : "कार्तिक",
      tithi: `शु. ${toMarathiDigits(d)}`,
      nakshatra: "अश्विनी",
      yoga: "विष्कंभ",
      karana: "बव",
      rashi: "तूळ",
      "festival 1": f1,
      "festival 2": f2,
      "festival 3": "",
      "festival 4": "",
      "festival 5": "",
      "festival 6": "",
      "festival 7": "",
      "festival 8": "",
      sunrise: "०६:४५",
      sunset: "१८:३०",
      moonrise: (isSank) ? "०८.५१" : "",
      isSankashti: isSank,
      isEkadashi: isEkad,
      isPurnima: isPour,
      isPournima: isPour,
      isAmavasya: isAmav
    });
  }
  return days;
}

function generateSampleDaysForYear(year) {
  const allDays = [];
  for (let m = 1; m <= 12; m++) {
    allDays.push(...generateSampleDaysForMonth(year, m));
  }
  return allDays;
}

function renderCalendarGrid() {
  const container = document.getElementById("calendarDaysGrid");
  if (!container) return;
  container.innerHTML = "";

  const monthHeading = document.getElementById("currentMonthHeading");
  if (monthHeading) {
    const shakaYear = currentYear === 2026 ? "१९४८" : "१९४९";
    monthHeading.innerHTML = `${MARATHI_MONTHS_NAMES[currentMonth - 1]} ${toMarathiDigits(currentYear)} <span class="text-sm font-normal text-slate-500">शके ${shakaYear}</span>`;
  }

  const monthDays = activeCalendarData.filter(d => d.month === currentMonth && d.year === currentYear);
  if (monthDays.length === 0) {
    container.innerHTML = `<div class="col-span-7 p-12 text-center text-slate-400">डेटा उपलब्ध नाही.</div>`;
    return;
  }

  const firstDayDt = new Date(currentYear, currentMonth - 1, 1);
  const startDayOfWeek = firstDayDt.getDay();

  for (let i = 0; i < startDayOfWeek; i++) {
    const emptyCell = document.createElement("div");
    emptyCell.className = "bg-slate-50 min-h-[95px] sm:min-h-[105px] border-b border-r border-slate-100";
    container.appendChild(emptyCell);
  }

  monthDays.forEach(day => {
    const cell = document.createElement("div");
    const isSun = day.dayOfWeekIndex === 1;
    const isRedNumber = isSun || day.isHoliday;

    let bgClass = "bg-white hover:bg-amber-50/60";
    if (day.isAmavasya) bgClass = "bg-slate-50/80 hover:bg-slate-100";
    else if (day.isPournima || day.isPurnima) bgClass = "bg-amber-50/40 hover:bg-amber-100/50";
    else if (day.isEkadashi) bgClass = "bg-orange-50/40 hover:bg-orange-100/50";
    else if (day.isSankashti) bgClass = "bg-rose-50/30 hover:bg-rose-100/40";

    cell.className = `${bgClass} min-h-[95px] sm:min-h-[105px] p-1.5 sm:p-2 flex flex-col justify-between cursor-pointer border-b border-r border-slate-200 transition relative group`;
    cell.onclick = () => openEditModal(day);

    const topRow = document.createElement("div");
    topRow.className = "flex items-center justify-between gap-1 leading-none";

    const leftBadge = document.createElement("div");
    if (day.isShubhDiwas) {
      leftBadge.className = "text-[9px] sm:text-[10px] font-bold text-red-600 bg-red-50 border border-red-200 px-1 py-0.5 rounded";
      leftBadge.textContent = "शुभ";
    }
    topRow.appendChild(leftBadge);

    const iconsRow = document.createElement("div");
    iconsRow.className = "flex items-center gap-0.5 sm:gap-1 text-xs";
    if (day.isEkadashi) iconsRow.innerHTML += `<span>🚩</span>`;
    if (day.isSankashti) iconsRow.innerHTML += `<span>🕉️</span>`;
    if (day.isPournima || day.isPurnima) iconsRow.innerHTML += `<span>🌕</span>`;
    if (day.isAmavasya) iconsRow.innerHTML += `<span>🌑</span>`;
    topRow.appendChild(iconsRow);

    cell.appendChild(topRow);

    const festCol = document.createElement("div");
    festCol.className = "my-0.5 sm:my-1 space-y-0.5";

    const f1 = (day["festival 1"] || "").trim();
    const f2 = (day["festival 2"] || "").trim();

    if (f1) {
      const f1El = document.createElement("div");
      f1El.className = `text-[10px] sm:text-[11px] leading-tight font-bold ${day.isHoliday ? 'text-red-700' : 'text-slate-800'} line-clamp-2`;
      f1El.textContent = f1;
      festCol.appendChild(f1El);
    }
    if (f2) {
      const f2El = document.createElement("div");
      f2El.className = "text-[9px] sm:text-[10px] leading-tight font-semibold text-slate-700 line-clamp-1";
      f2El.textContent = f2;
      festCol.appendChild(f2El);
    }
    cell.appendChild(festCol);

    const bottomRow = document.createElement("div");
    bottomRow.className = "flex items-baseline justify-between mt-auto";

    const tithiEl = document.createElement("span");
    tithiEl.className = "text-[9px] sm:text-[10px] text-slate-500 font-medium truncate max-w-[65%]";
    tithiEl.textContent = day.tithi || "";
    bottomRow.appendChild(tithiEl);

    const dateNum = document.createElement("span");
    dateNum.className = `text-xl sm:text-2xl font-black ${isRedNumber ? 'text-red-600' : 'text-slate-900'}`;
    dateNum.textContent = toMarathiDigits(day.day);
    bottomRow.appendChild(dateNum);

    cell.appendChild(bottomRow);
    container.appendChild(cell);
  });
}

function openEditModal(day) {
  selectedDayData = day;

  document.getElementById("modalDayNumber").textContent = toMarathiDigits(day.day);
  document.getElementById("modalDateTitle").textContent = `${toMarathiDigits(day.day)} ${MARATHI_MONTHS_NAMES[day.month - 1]} ${toMarathiDigits(day.year)} - ${day.dayOfWeek}`;

  document.getElementById("inputFestival1").value = day["festival 1"] || "";
  document.getElementById("inputFestival2").value = day["festival 2"] || "";
  document.getElementById("inputFestival3").value = day["festival 3"] || "";
  document.getElementById("inputFestival4").value = day["festival 4"] || "";
  document.getElementById("inputFestival5").value = day["festival 5"] || "";
  document.getElementById("inputFestival6").value = day["festival 6"] || "";
  if (document.getElementById("inputFestival7")) document.getElementById("inputFestival7").value = day["festival 7"] || "";
  if (document.getElementById("inputFestival8")) document.getElementById("inputFestival8").value = day["festival 8"] || "";

  document.getElementById("checkIsHoliday").checked = !!day.isHoliday;
  document.getElementById("checkIsShubhDiwas").checked = !!day.isShubhDiwas;
  document.getElementById("checkIsEkadashi").checked = !!day.isEkadashi;
  document.getElementById("checkIsSankashti").checked = !!day.isSankashti;
  document.getElementById("checkIsPournima").checked = !!(day.isPournima || day.isPurnima);
  document.getElementById("checkIsAmavasya").checked = !!day.isAmavasya;

  document.getElementById("inputMarathiMonth").value = day.marathiMonth || "";
  document.getElementById("inputTithi").value = day.tithi || "";
  document.getElementById("inputNakshatra").value = day.nakshatra || "";
  document.getElementById("inputYoga").value = day.yoga || "";
  document.getElementById("inputKarana").value = day.karana || "";
  document.getElementById("inputRashi").value = day.rashi || "";
  document.getElementById("inputSunrise").value = day.sunrise || "०६:४५";
  document.getElementById("inputSunset").value = day.sunset || "१८:३०";
  document.getElementById("inputMoonrise").value = day.moonrise || "";

  document.getElementById("editModal").classList.remove("hidden");
}

function closeEditModal() {
  const modal = document.getElementById("editModal");
  if (modal) modal.classList.add("hidden");
  selectedDayData = null;
}

function saveModalChanges() {
  if (!selectedDayData) return;

  selectedDayData["festival 1"] = document.getElementById("inputFestival1").value.trim();
  selectedDayData["festival 2"] = document.getElementById("inputFestival2").value.trim();
  selectedDayData["festival 3"] = document.getElementById("inputFestival3").value.trim();
  selectedDayData["festival 4"] = document.getElementById("inputFestival4").value.trim();
  selectedDayData["festival 5"] = document.getElementById("inputFestival5").value.trim();
  selectedDayData["festival 6"] = document.getElementById("inputFestival6").value.trim();
  if (document.getElementById("inputFestival7")) selectedDayData["festival 7"] = document.getElementById("inputFestival7").value.trim();
  if (document.getElementById("inputFestival8")) selectedDayData["festival 8"] = document.getElementById("inputFestival8").value.trim();

  selectedDayData.isHoliday = document.getElementById("checkIsHoliday").checked;
  selectedDayData.isShubhDiwas = document.getElementById("checkIsShubhDiwas").checked;
  selectedDayData.isEkadashi = document.getElementById("checkIsEkadashi").checked;
  selectedDayData.isSankashti = document.getElementById("checkIsSankashti").checked;
  const isPurnimaVal = document.getElementById("checkIsPournima").checked;
  selectedDayData.isPournima = isPurnimaVal;
  selectedDayData.isPurnima = isPurnimaVal;
  selectedDayData.isAmavasya = document.getElementById("checkIsAmavasya").checked;

  selectedDayData.marathiMonth = document.getElementById("inputMarathiMonth").value.trim();
  selectedDayData.tithi = document.getElementById("inputTithi").value.trim();
  selectedDayData.nakshatra = document.getElementById("inputNakshatra").value.trim();
  selectedDayData.yoga = document.getElementById("inputYoga").value.trim();
  selectedDayData.karana = document.getElementById("inputKarana").value.trim();
  selectedDayData.rashi = document.getElementById("inputRashi").value.trim();
  selectedDayData.sunrise = document.getElementById("inputSunrise").value.trim();
  selectedDayData.sunset = document.getElementById("inputSunset").value.trim();
  selectedDayData.moonrise = document.getElementById("inputMoonrise").value.trim();

  renderCalendarGrid();
  calendarDataCache[currentYear] = activeCalendarData;
  try {
    sessionStorage.setItem(`ved_cal_${currentYear}`, JSON.stringify(activeCalendarData));
    localStorage.setItem(`ved_draft_cal_${currentYear}`, JSON.stringify(activeCalendarData));
  } catch (_) {}
  setHasUnsavedChanges(true);
  showAlert(`${toMarathiDigits(selectedDayData.day)} ${MARATHI_MONTHS_NAMES[selectedDayData.month - 1]} चे बदल जतन झाले आहेत! (पब्लिश करणे शिल्लक)`, "green");
  closeEditModal();
}

// १५. स्थानिक .enc एक्सपोर्ट
async function exportEncryptedFile() {
  try {
    showAlert("AES-256 GCM ने फाईल एन्क्रिप्ट करत आहे...", "blue");
    const jsonStr = JSON.stringify(activeCalendarData, null, 2);
    const encryptedBytes = await encryptPayload(jsonStr);

    const blob = new Blob([encryptedBytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `calendar_data_${currentYear}.enc`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showAlert(`✓ calendar_data_${currentYear}.enc डाऊनलोड झाली!`, "green");
  } catch (err) {
    showAlert("एन्क्रिप्शन त्रुटी: " + err.message, "red");
  }
}

// १६. महिना टॅब्स व इव्हेंट्स
function setupMonthTabs() {
  const container = document.getElementById("monthTabsContainer");
  if (!container) return;
  container.innerHTML = "";

  MARATHI_MONTHS_NAMES.forEach((name, idx) => {
    const monthNum = idx + 1;
    const btn = document.createElement("button");
    const isActive = monthNum === currentMonth;
    btn.className = `px-3 py-1.5 text-xs font-bold rounded-lg transition whitespace-nowrap ${
      isActive ? 'bg-[#800000] text-white shadow-sm' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
    }`;
    btn.textContent = name;
    btn.onclick = () => {
      currentMonth = monthNum;
      setupMonthTabs();
      renderCalendarGrid();
    };
    container.appendChild(btn);
  });
}

function updateYearButtonStyles() {
  const btn2026 = document.getElementById("btnYear2026");
  const btn2027 = document.getElementById("btnYear2027");
  if (!btn2026 || !btn2027) return;

  if (currentYear === 2026) {
    btn2026.className = "px-4 py-1.5 text-sm font-bold rounded-lg bg-[#800000] text-white shadow-sm transition";
    btn2027.className = "px-4 py-1.5 text-sm font-bold rounded-lg text-slate-600 hover:text-slate-900 transition";
  } else {
    btn2027.className = "px-4 py-1.5 text-sm font-bold rounded-lg bg-[#800000] text-white shadow-sm transition";
    btn2026.className = "px-4 py-1.5 text-sm font-bold rounded-lg text-slate-600 hover:text-slate-900 transition";
  }
}

function setupEventListeners() {
  const btnExport = document.getElementById("btnExportEnc");
  if (btnExport) btnExport.onclick = exportEncryptedFile;

  const btnPublish = document.getElementById("btnPublishGitHub");
  if (btnPublish) btnPublish.onclick = publishToGitHubLive;

  const btnLoadGit = document.getElementById("btnLoadGitHub");
  if (btnLoadGit) btnLoadGit.onclick = loadLiveDataFromGitHub;

  const modalClose = document.getElementById("modalCloseBtn");
  if (modalClose) modalClose.onclick = closeEditModal;

  const modalCancel = document.getElementById("modalCancelBtn");
  if (modalCancel) modalCancel.onclick = closeEditModal;

  const modalSave = document.getElementById("modalSaveDayBtn");
  if (modalSave) modalSave.onclick = saveModalChanges;

  const btnUnlock = document.getElementById("btnUnlockWithPin");
  if (btnUnlock) btnUnlock.onclick = handleUnlockWithPin;

  const inputPin = document.getElementById("inputPinCode");
  if (inputPin) {
    inputPin.onkeydown = (e) => {
      if (e.key === "Enter") handleUnlockWithPin();
    };
  }

  const btnCreateVault = document.getElementById("btnCreateVaultWithPin");
  if (btnCreateVault) btnCreateVault.onclick = handleCreateVaultWithPin;

  const btnLogout = document.getElementById("btnLogoutDashboard") || document.getElementById("btnLockDashboard");
  if (btnLogout) {
    btnLogout.onclick = () => {
      // १. सर्व सेशन व तात्पुरती मेमरी पूर्ण साफ करणे
      sessionStorage.clear();
      localStorage.removeItem("ved_github_token");
      localStorage.removeItem("ved_admin_unlocked");
      cachedVaultBytes = null;
      cryptoKey = null;

      // २. इनपुट बॉक्स क्लिअर करणे
      const pinInput = document.getElementById("inputPinCode");
      if (pinInput) pinInput.value = "";
      const errEl = document.getElementById("pinErrorMsg");
      if (errEl) errEl.classList.add("hidden");

      // ३. स्क्रीन त्वरित पिन-लॉक करणे
      const modal = document.getElementById("pinLockModal");
      if (modal) modal.classList.remove("hidden");

      updateGitHubConnectionStatus();
      showAlert("✓ तुम्ही यशस्वीरित्या लॉगआउट झाला आहात! सर्व सेशन सुरक्षित क्लिअर झाले आहे.", "blue");

      setTimeout(() => {
        if (pinInput) pinInput.focus();
      }, 200);
    };
  }

  const btnSettings = document.getElementById("btnSettings");
  if (btnSettings) {
    btnSettings.onclick = () => {
      const modal = document.getElementById("settingsModal");
      if (modal) modal.classList.remove("hidden");
    };
  }

  const btnToggleTok = document.getElementById("btnToggleTokenVisibility");
  if (btnToggleTok) {
    btnToggleTok.onclick = () => {
      const inp = document.getElementById("inputGitHubToken");
      if (inp.type === "password") {
        inp.type = "text";
        btnToggleTok.textContent = "🙈 लपवा";
      } else {
        inp.type = "password";
        btnToggleTok.textContent = "👁️ दाखवा";
      }
    };
  }

  const btnSaveTok = document.getElementById("btnSaveToken");
  if (btnSaveTok) {
    btnSaveTok.onclick = () => {
      const token = document.getElementById("inputGitHubToken").value.trim();
      const repo = document.getElementById("inputRepoName").value.trim();
      const branch = document.getElementById("inputBranchName").value.trim();

      if (token) localStorage.setItem("ved_github_token", token);
      if (repo) localStorage.setItem("ved_github_repo", repo);
      if (branch) localStorage.setItem("ved_github_branch", branch);

      updateGitHubConnectionStatus();
      showAlert("✓ GitHub टोकन सेव्ह झाले!", "green");
    };
  }

  const btn2026 = document.getElementById("btnYear2026");
  const btn2027 = document.getElementById("btnYear2027");

  if (btn2026) {
    btn2026.onclick = async () => {
      currentYear = 2026;
      updateYearButtonStyles();
      if (!calendarDataCache[2026] || calendarDataCache[2026].length === 0) {
        await loadCalendarDataForYear(2026);
      }
      activeCalendarData = calendarDataCache[2026];
      setupMonthTabs();
      renderCalendarGrid();
    };
  }

  if (btn2027) {
    btn2027.onclick = async () => {
      currentYear = 2027;
      updateYearButtonStyles();
      if (!calendarDataCache[2027] || calendarDataCache[2027].length === 0) {
        await loadCalendarDataForYear(2027);
      }
      activeCalendarData = calendarDataCache[2027];
      setupMonthTabs();
      renderCalendarGrid();
    };
  }

  // जाहिरात व सेटिंग्ज बदलांवरही पब्लिश बटन सक्रिय करणे
  const adFlagIds = ["cfgEnableAds", "cfgEnableNativeAds", "cfgEnableBanner", "cfgEnableInterstitial", "cfgInterstitialInterval", "cfgForceTestAds", "cfgEnableStatusShare"];
  adFlagIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", () => {
        setHasUnsavedChanges(true);
      });
    }
  });

  updatePublishButtonState();
}

// १७. ॲप इनिशिअलायझेशन & व्हॉल्ट ऑटो-डिटेक्ट
async function initApp() {
  try {
    // Purge any legacy plaintext token from persistent localStorage
    localStorage.removeItem("ved_github_token");

    // १. WebCrypto की त्वरित तयार करा जेणेकरून डेटा तात्काळ डिक्रिप्ट करता येईल
    await initCryptoKey();

    setupMonthTabs();
    setupEventListeners();

    const savedRepo = localStorage.getItem("ved_github_repo") || "rushikesh143143/VedDindarshika";
    const savedBranch = localStorage.getItem("ved_github_branch") || "main";

    if (document.getElementById("inputRepoName")) document.getElementById("inputRepoName").value = savedRepo;
    if (document.getElementById("inputBranchName")) document.getElementById("inputBranchName").value = savedBranch;

    updateGitHubConnectionStatus();

    // २. पेज उघडताच २०२६ आणि २०२७ चे खरेखुरे डेटा समांतर (Parallel) लोड करा!
    await loadBothYears(false);

    // ३. सेशन लॉक स्थिती तपासा
    const isUnlocked = sessionStorage.getItem("ved_admin_unlocked") === "true";
    const sessionToken = sessionStorage.getItem("ved_github_token");

    // Fetch admin_vault.enc
    try {
      const res = await fetch(`admin_vault.enc?t=${Date.now()}`);
      if (res.ok) {
        const buf = await res.arrayBuffer();
        cachedVaultBytes = new Uint8Array(buf);
      }
    } catch (_) {}

    if (isUnlocked && sessionToken) {
      document.getElementById("pinLockModal").classList.add("hidden");
      updatePublishButtonState();
      // जर आधीच अनलॉक असेल आणि न पब्लिश केलेले बदल नसतील तरच GitHub वरून ताजे बदल आणा
      if (!getHasUnsavedChanges()) {
        loadLiveDataFromGitHub().catch(e => console.warn(e));
      }
    } else {
      // ALWAYS keep locked until PIN is entered
      document.getElementById("pinLockModal").classList.remove("hidden");
      setTimeout(() => {
        const inp = document.getElementById("inputPinCode");
        if (inp) inp.focus();
      }, 200);
    }

  } catch (err) {
    console.error("Dashboard init error:", err);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
