"use strict";

// ECDSA page controller. Network calls go through api-client.js.
const ECDSA_CURVE = Object.freeze({
    p: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
    n: BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
    gx: BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    gy: BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
});

function parseHex(value, field) {
    const normalized = String(value ?? "").trim().replace(/^0x/i, "");
    if (!/^[0-9a-f]+$/i.test(normalized)) throw new Error(`${field} must be hexadecimal`);
    return BigInt(`0x${normalized}`);
}

function modInverse(a, m) {
    a = ((a % m) + m) % m;
    let oldR = a, r = m, oldS = 1n, s = 0n;
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    if (oldR !== 1n) throw new Error("Modular inverse does not exist");
    return ((oldS % m) + m) % m;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setValue(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value;
}

function show(id) { document.getElementById(id)?.classList.remove("d-none"); }
function hide(id) { document.getElementById(id)?.classList.add("d-none"); }

function displayCurveParameters() {
    setText("param-p", ECDSA_CURVE.p.toString(16));
    setText("param-n", ECDSA_CURVE.n.toString(16));
    setText("param-gx", ECDSA_CURVE.gx.toString(16));
    setText("param-gy", ECDSA_CURVE.gy.toString(16));
}

function displayResults(data) {
    const container = document.getElementById("signatures");
    if (!container) return;
    container.replaceChildren();
    const signatures = Array.isArray(data.signatures) ? data.signatures : [];
    signatures.forEach((sig, index) => {
        const card = document.createElement("div");
        card.className = "mb-3";
        const title = document.createElement("h6");
        title.textContent = `Signature #${index + 1}`;
        card.appendChild(title);
        for (const [label, value] of [["Message Hash (z)", sig.message], ["r", sig.r], ["s", sig.s]]) {
            const p = document.createElement("p");
            const strong = document.createElement("strong");
            strong.textContent = `${label}: `;
            const span = document.createElement("span");
            span.className = "text-monospace";
            span.textContent = value ?? "Unavailable";
            p.append(strong, span);
            card.appendChild(p);
        }
        container.appendChild(card);
    });
    setText("verify-result", signatures.length ? `${signatures.length} signature(s) loaded` : "No signatures found");
    setText("point-valid", "Not verified");
}

async function performAnalysis() {
    const txId = document.getElementById("tx-id")?.value.trim();
    if (!txId) {
        setText("analysis-error", "Transaction ID is required");
        show("analysis-error");
        return;
    }
    show("analysis-loading");
    hide("analysis-error");
    hide("analysis-results");
    try {
        const data = await window.apiClient.analyzeTransaction(txId);
        displayResults(data);
        show("analysis-results");
    } catch (error) {
        setText("analysis-error", error.message || "Transaction analysis failed");
        show("analysis-error");
    } finally {
        hide("analysis-loading");
    }
}

function calculateLocalNonce() {
    try {
        const m1 = parseHex(document.getElementById("verify-m1")?.value, "m1");
        const m2 = parseHex(document.getElementById("verify-m2")?.value, "m2");
        const s1 = parseHex(document.getElementById("verify-s1")?.value, "s1");
        const s2 = parseHex(document.getElementById("verify-s2")?.value, "s2");
        const diff = ((s1 - s2) % ECDSA_CURVE.n + ECDSA_CURVE.n) % ECDSA_CURVE.n;
        if (diff === 0n) throw new Error("S values are identical");
        const zDiff = ((m1 - m2) % ECDSA_CURVE.n + ECDSA_CURVE.n) % ECDSA_CURVE.n;
        const k = zDiff * modInverse(diff, ECDSA_CURVE.n) % ECDSA_CURVE.n;
        setText("calculated-k", `0x${k.toString(16)}`);
        setValue("verify-k", k.toString(16));
    } catch (error) { setText("calculated-k", error.message); }
}

function calculateLocalPrivateKey() {
    try {
        const r = parseHex(document.getElementById("verify-r")?.value, "r");
        const s = parseHex(document.getElementById("verify-s")?.value, "s");
        const z = parseHex(document.getElementById("verify-m")?.value, "z");
        const k = parseHex(document.getElementById("verify-k")?.value, "k");
        if (r <= 0n || r >= ECDSA_CURVE.n) throw new Error("r is outside the valid range");
        const x = (((s * k - z) % ECDSA_CURVE.n + ECDSA_CURVE.n) % ECDSA_CURVE.n) * modInverse(r, ECDSA_CURVE.n) % ECDSA_CURVE.n;
        if (x === 0n) throw new Error("Calculated private key is invalid");
        setText("calculated-x", `0x${x.toString(16)}`);
        setValue("verify-private-key", x.toString(16));
        setText("sig-verification-result", "Calculated value only; this UI does not claim cryptographic signature verification.");
    } catch (error) { setText("calculated-x", error.message); }
}

window.addEventListener("DOMContentLoaded", () => {
    displayCurveParameters();
    document.getElementById("ecdsa-analysis-form")?.addEventListener("submit", (event) => {
        event.preventDefault();
        performAnalysis();
    });
    document.getElementById("verify-k-btn")?.addEventListener("click", calculateLocalNonce);
    document.getElementById("verify-x-btn")?.addEventListener("click", calculateLocalPrivateKey);
});
