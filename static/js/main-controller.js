"use strict";

// Shared UI controller. All backend calls go through api-client.js.
const UI = {
    get: (id) => document.getElementById(id),
    text: (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value ?? ""; },
    visible: (id, value) => { const el = document.getElementById(id); if (el) el.classList.toggle("d-none", !value); },
};

function showLoading(type) { UI.visible(`${type}-loading`, true); }
function hideLoading(type) { UI.visible(`${type}-loading`, false); }
function showError(type, message) { UI.text(`${type}-error`, message); UI.visible(`${type}-error`, true); }
function hideError(type) { UI.visible(`${type}-error`, false); }

async function analyzeTransaction(txId) {
    showLoading("analysis"); hideError("analysis");
    try { displayTransactionResults(await window.apiClient.analyzeTransaction(txId)); }
    catch (error) { showError("analysis", error.message || "Transaction analysis failed"); }
    finally { hideLoading("analysis"); }
}

async function analyzeAddress(address) {
    showLoading("address"); hideError("address");
    const maxTxs = Math.max(1, Math.min(parseInt(UI.get("btc-max-txs")?.value || "500", 10) || 500, 5000));
    try { displayAddressResults(await window.apiClient.scanAddress(address, maxTxs)); }
    catch (error) { showError("address", error.message || "Address vulnerability scan failed"); }
    finally { hideLoading("address"); }
}

function initForms() {
    UI.get("tx-analysis-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const txId = UI.get("tx-id")?.value.trim();
        if (!txId || (typeof validateTransactionId === "function" && !validateTransactionId(txId))) return showError("analysis", "Invalid transaction ID format");
        await analyzeTransaction(txId);
    });

    UI.get("address-analysis-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const address = UI.get("btc-address")?.value.trim();
        if (!address || (typeof validateBitcoinAddress === "function" && !validateBitcoinAddress(address))) return showError("address", "Invalid Bitcoin address format");
        await analyzeAddress(address);
    });
}

function displayTransactionResults(data) {
    UI.visible("analysis-results", true);
    UI.text("result-txid", data?.tx_id || "N/A");
    UI.text("result-sigs", data?.signatures_analyzed ?? 0);
    UI.text("result-weak", Array.isArray(data?.weak_signatures) ? data.weak_signatures.length : 0);
    UI.text("result-keys", data?.private_keys_found ?? 0);
    const table = UI.get("weak-sigs-table");
    if (!table) return;
    table.replaceChildren();
    const findings = Array.isArray(data?.weak_signatures) ? data.weak_signatures : [];
    if (!findings.length) {
        const row = table.insertRow(); const cell = row.insertCell(); cell.colSpan = 3; cell.textContent = "No weak signatures found"; return;
    }
    for (const finding of findings) {
        const row = table.insertRow();
        row.insertCell().textContent = finding?.type || "Unknown";
        row.insertCell().textContent = finding?.details || "N/A";
        const cell = row.insertCell();
        if (finding?.private_key) {
            const button = document.createElement("button"); button.className = "btn btn-sm btn-warning"; button.textContent = "View Key";
            button.addEventListener("click", () => showPrivateKey(finding.private_key)); cell.appendChild(button);
        }
    }
}

function displayAddressResults(data) {
    UI.visible("address-results", true);
    for (const [id, value] of Object.entries({
        "result-address": data?.address || "N/A", "result-total-txs": data?.total_tx_count ?? 0,
        "result-txs-analyzed": data?.transactions_analyzed ?? 0, "result-sigs-total": data?.signatures_total ?? 0,
        "result-low-s": data?.low_s_count ?? 0, "result-schnorr": data?.schnorr_count ?? 0,
        "result-z-na": data?.z_unavailable ?? 0, "result-elapsed": data?.elapsed_s ? `${Number(data.elapsed_s).toFixed(1)} s` : "-",
        "reused-groups-count": (data?.reused_r_groups || []).length,
        "cross-tx-count": (data?.cross_tx_reused_r || []).length,
        "in-tx-count": (data?.in_tx_reused_r || []).length,
        "bias-count": (data?.biased_nonce_candidates || []).length,
    })) UI.text(id, value);

    UI.text("finding-risk", data?.risk_level || "unknown");
    UI.text("finding-summary", data?.finding_summary || "No finding summary available.");

    renderRows("result-sigs-by-type", Object.entries(data?.signatures_by_type || {}).sort((a, b) => b[1] - a[1]), (row, [key, value]) => { row.insertCell().textContent = key; row.insertCell().textContent = value; }, 2);
    renderRows("reused-groups-body", (data?.reused_r_groups || []).slice(0, 100), (row, item) => { row.insertCell().textContent = shortHex(item.r); row.insertCell().textContent = item.occurrences ?? "-"; row.insertCell().textContent = item.unique_txs ?? "-"; row.insertCell().textContent = (item.tx_sample || []).join(", "); }, 4);
    renderRows("cross-tx-body", (data?.cross_tx_reused_r || []).slice(0, 200), (row, item) => { row.insertCell().textContent = shortHex(item.r); row.insertCell().textContent = item.tx_a || ""; row.insertCell().textContent = item.vin_a ?? "-"; row.insertCell().textContent = item.tx_b || ""; row.insertCell().textContent = item.vin_b ?? "-"; row.insertCell().textContent = `${item.script_type_a || "?"} / ${item.script_type_b || "?"}`; }, 6);
    renderRows("in-tx-body", (data?.in_tx_reused_r || []).slice(0, 200), (row, item) => { row.insertCell().textContent = shortHex(item.r); row.insertCell().textContent = item.txid || ""; row.insertCell().textContent = `${item.vin_a ?? "-"} / ${item.vin_b ?? "-"}`; row.insertCell().textContent = `${item.script_type_a || "?"} / ${item.script_type_b || "?"}`; }, 4);
    renderRows("bias-body", (data?.biased_nonce_candidates || []).slice(0, 200), (row, item) => { row.insertCell().textContent = item.txid || ""; row.insertCell().textContent = item.input_index ?? "-"; row.insertCell().textContent = item.k_bits ?? "-"; row.insertCell().textContent = shortHex(item.k); }, 4);

    // The safe address-scan endpoint intentionally strips private-key material.
    UI.text("recovered-keys-count", data?.recovered_key_count ?? 0);
    UI.visible("recovered-keys-card", false);
}

function renderRows(targetId, items, renderer, colspan) {
    const target = UI.get(targetId); if (!target) return; target.replaceChildren();
    if (!items.length) { const row = target.insertRow(); const cell = row.insertCell(); cell.colSpan = colspan; cell.className = "text-muted"; cell.textContent = "none"; return; }
    items.forEach(item => renderer(target.insertRow(), item));
}

async function loadKnownAddresses() {
    const tbody = UI.get("known-addresses")?.querySelector("tbody"); if (!tbody) return;
    tbody.replaceChildren();
    try {
        const addresses = await window.apiClient.knownAddresses();
        if (!Array.isArray(addresses) || !addresses.length) { const row = tbody.insertRow(); const cell = row.insertCell(); cell.colSpan = 3; cell.textContent = "No addresses found"; return; }
        for (const address of addresses) {
            const row = tbody.insertRow(); row.insertCell().textContent = address; row.insertCell().textContent = "Potentially Vulnerable";
            const button = document.createElement("button"); button.className = "btn btn-sm btn-primary"; button.textContent = "Analyze";
            button.addEventListener("click", () => { window.location.href = `/address?addr=${encodeURIComponent(address)}`; }); row.insertCell().appendChild(button);
        }
    } catch (error) { const row = tbody.insertRow(); const cell = row.insertCell(); cell.colSpan = 3; cell.textContent = `Error loading addresses: ${error.message}`; }
}

function setScanButtonsDisabled(disabled) { ["scan-recent-btn", "monitor-mempool-btn"].forEach(id => { const button = UI.get(id); if (button) button.disabled = disabled; }); }

async function runLiveScan(type) {
    UI.visible("live-scan-loading", true); UI.visible("live-scan-results", false); setScanButtonsDisabled(true);
    try { displayLiveScanResults(type === "recent" ? await window.apiClient.autoScan() : await window.apiClient.monitorMempool(), type); }
    catch (error) { displayLiveScanResults({ success: false, error: error.message }, type); }
    finally { UI.visible("live-scan-loading", false); setScanButtonsDisabled(false); }
}

function displayLiveScanResults(data, type) {
    UI.visible("live-scan-results", true);
    const summary = UI.get("scan-summary"), results = UI.get("vulnerable-transactions"); if (!summary || !results) return;
    results.replaceChildren();
    if (!data?.success) { summary.className = "alert alert-danger"; summary.textContent = data?.error || "Scan failed"; return; }
    const scanned = type === "recent" ? data.scanned_transactions : data.mempool_scanned;
    const found = type === "recent" ? data.weak_signatures_found : data.vulnerable_transactions;
    summary.className = `alert ${found ? "alert-warning" : "alert-success"}`; summary.textContent = `Scanned ${scanned ?? 0} transaction(s); ${found ?? 0} result(s).`;
    for (const item of data.results || []) {
        const card = document.createElement("div"); card.className = "card mb-2";
        const body = document.createElement("div"); body.className = "card-body"; body.textContent = `Transaction: ${item.tx_id} | Findings: ${item.private_keys_found ?? 0}`;
        const button = document.createElement("button"); button.className = "btn btn-sm btn-primary ms-2"; button.textContent = "Analyze Details"; button.addEventListener("click", () => goToTransaction(item.tx_id));
        body.appendChild(button); card.appendChild(body); results.appendChild(card);
    }
}

function showPrivateKey(key) { if (confirm("Warning: you are about to view a private key. Continue?")) alert(`Private key (hex):\n${key}`); }
function goToTransaction(txId) { window.location.href = `/transaction?tx=${encodeURIComponent(txId)}`; }
function shortHex(value) { const text = String(value ?? "-"); return text.length > 18 ? `${text.slice(0, 10)}...${text.slice(-6)}` : text; }

window.addEventListener("DOMContentLoaded", () => {
    initForms();
    UI.get("scan-recent-btn")?.addEventListener("click", () => runLiveScan("recent"));
    UI.get("monitor-mempool-btn")?.addEventListener("click", () => runLiveScan("mempool"));
    if (UI.get("known-addresses")) loadKnownAddresses();

    const params = new URLSearchParams(window.location.search);
    const txId = params.get("tx");
    if (txId && UI.get("tx-analysis-form") && UI.get("tx-id")) {
        UI.get("tx-id").value = txId;
        setTimeout(() => UI.get("tx-analysis-form").dispatchEvent(new Event("submit")), 100);
    }

    const address = params.get("addr");
    if (address && UI.get("address-analysis-form") && UI.get("btc-address")) {
        UI.get("btc-address").value = address;
        setTimeout(() => UI.get("address-analysis-form").dispatchEvent(new Event("submit")), 100);
    }
});
