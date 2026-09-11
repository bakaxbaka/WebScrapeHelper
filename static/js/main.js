"use strict";

// Shared UI controller. All backend calls are delegated to api-client.js.

document.addEventListener("DOMContentLoaded", () => {
    initTransactionForm();
    initAddressForm();
    initLiveScanning();
    initTransactionAnalysis();
    if (document.getElementById("known-addresses")) loadKnownAddresses();
});

const $ = (id) => document.getElementById(id);
const setText = (id, value) => { const el = $(id); if (el) el.textContent = value ?? ""; };
const toggle = (id, visible) => { const el = $(id); if (el) el.classList.toggle("d-none", !visible); };

function showLoading(type) { toggle(`${type}-loading`, true); }
function hideLoading(type) { toggle(`${type}-loading`, false); }
function showError(type, message) { setText(`${type}-error`, message); toggle(`${type}-error`, true); }
function hideError(type) { toggle(`${type}-error`, false); }

function initTransactionForm() {
    $("tx-analysis-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const txId = $("tx-id")?.value.trim();
        if (!txId || (typeof validateTransactionId === "function" && !validateTransactionId(txId))) {
            showError("analysis", "Invalid transaction ID format");
            return;
        }
        await analyzeTransaction(txId);
    });
}

function initAddressForm() {
    $("address-analysis-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const address = $("btc-address")?.value.trim();
        if (!address || (typeof validateBitcoinAddress === "function" && !validateBitcoinAddress(address))) {
            showError("address", "Invalid Bitcoin address format");
            return;
        }
        await analyzeAddress(address);
    });
}

async function analyzeTransaction(txId) {
    showLoading("analysis");
    hideError("analysis");
    try {
        const data = await window.apiClient.analyzeTransaction(txId);
        displayTransactionResults(data);
    } catch (error) {
        showError("analysis", error.message || "Transaction analysis failed");
    } finally {
        hideLoading("analysis");
    }
}

async function analyzeAddress(address) {
    showLoading("address");
    hideError("address");
    const maxTxs = Math.max(1, Math.min(parseInt($("btc-max-txs")?.value || "500", 10) || 500, 5000));
    try {
        const data = await window.apiClient.analyzeAddress(address, maxTxs);
        displayAddressResults(data);
    } catch (error) {
        showError("address", error.message || "Address analysis failed");
    } finally {
        hideLoading("address");
    }
}

function displayTransactionResults(data) {
    toggle("analysis-results", true);
    setText("result-txid", data?.tx_id || "N/A");
    setText("result-sigs", data?.signatures_analyzed ?? 0);
    setText("result-weak", Array.isArray(data?.weak_signatures) ? data.weak_signatures.length : 0);
    setText("result-keys", data?.private_keys_found ?? 0);

    const table = $("weak-sigs-table");
    if (!table) return;
    table.replaceChildren();
    const weaknesses = Array.isArray(data?.weak_signatures) ? data.weak_signatures : [];
    if (!weaknesses.length) {
        const row = table.insertRow();
        row.insertCell().colSpan = 3;
        row.cells[0].textContent = "No weak signatures found";
        row.cells[0].className = "text-center";
        return;
    }
    for (const sig of weaknesses) {
        const row = table.insertRow();
        row.insertCell().textContent = sig?.type || "Unknown";
        row.insertCell().textContent = sig?.details || "N/A";
        const action = row.insertCell();
        if (sig?.private_key) {
            const button = document.createElement("button");
            button.className = "btn btn-sm btn-warning";
            button.textContent = "View Key";
            button.addEventListener("click", () => showPrivateKey(sig.private_key));
            action.appendChild(button);
        }
    }
}

function displayAddressResults(data) {
    toggle("address-results", true);
    setText("result-address", data?.address || "N/A");
    setText("result-total-txs", data?.total_tx_count ?? 0);
    setText("result-txs-analyzed", data?.transactions_analyzed ?? 0);
    setText("result-sigs-total", data?.signatures_total ?? 0);
    setText("result-low-s", data?.low_s_count ?? 0);
    setText("result-schnorr", data?.schnorr_count ?? 0);
    setText("result-z-na", data?.z_unavailable ?? 0);
    setText("result-elapsed", data?.elapsed_s ? `${Number(data.elapsed_s).toFixed(1)} s` : "-");

    renderRows("result-sigs-by-type", Object.entries(data?.signatures_by_type || {}).sort((a, b) => b[1] - a[1]), (row, entry) => {
        row.insertCell().textContent = entry[0];
        row.insertCell().textContent = entry[1];
    }, 2);
    renderRows("reused-groups-body", (data?.reused_r_groups || []).slice(0, 100), (row, item) => {
        row.insertCell().textContent = shortHex(item.r);
        row.insertCell().textContent = item.occurrences ?? "-";
        row.insertCell().textContent = item.unique_txs ?? "-";
        row.insertCell().textContent = item.tx_sample?.[0] || "";
    }, 4);
    renderRows("cross-tx-body", (data?.cross_tx_reused_r || []).slice(0, 200), (row, item) => {
        row.insertCell().textContent = shortHex(item.r);
        row.insertCell().textContent = item.tx_a || "";
        row.insertCell().textContent = item.vin_a ?? "-";
        row.insertCell().textContent = item.tx_b || "";
        row.insertCell().textContent = item.vin_b ?? "-";
        row.insertCell().textContent = `${item.script_type_a || "?"} / ${item.script_type_b || "?"}`;
    }, 6);

    const recovered = data?.recovered_keys || [];
    setText("recovered-keys-count", recovered.length);
    toggle("recovered-keys-card", recovered.length > 0);
    renderRows("recovered-keys-body", recovered, (row, item) => {
        row.insertCell().textContent = item.private_key_hex || "";
        row.insertCell().textContent = `${item.wif_compressed || ""}\n${item.wif_uncompressed || ""}`;
        row.insertCell().textContent = `${item.address_compressed || ""}\n${item.address_uncompressed || ""}`;
        row.insertCell().textContent = item.recovered_via || "unknown";
    }, 4);
}

function renderRows(targetId, items, renderer, emptyColspan = 1) {
    const target = $(targetId);
    if (!target) return;
    const tbody = target.tagName === "TBODY" ? target : target;
    tbody.replaceChildren();
    if (!items.length) {
        const row = tbody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = emptyColspan;
        cell.className = "text-muted";
        cell.textContent = "none";
        return;
    }
    for (const item of items) renderer(tbody.insertRow(), item);
}

async function loadKnownAddresses() {
    const table = $("known-addresses");
    const tbody = table?.querySelector("tbody");
    if (!tbody) return;
    tbody.replaceChildren();
    try {
        const addresses = await window.apiClient.knownAddresses();
        for (const address of Array.isArray(addresses) ? addresses : []) {
            const row = tbody.insertRow();
            row.insertCell().textContent = address;
            row.insertCell().textContent = "Potentially Vulnerable";
            const action = row.insertCell();
            const button = document.createElement("button");
            button.className = "btn btn-sm btn-primary";
            button.textContent = "Analyze";
            button.addEventListener("click", () => { window.location.href = `/address?addr=${encodeURIComponent(address)}`; });
            action.appendChild(button);
        }
        if (!addresses?.length) {
            const row = tbody.insertRow();
            row.insertCell().colSpan = 3;
            row.cells[0].textContent = "No addresses found";
        }
    } catch (error) {
        const row = tbody.insertRow();
        row.insertCell().colSpan = 3;
        row.cells[0].textContent = `Error loading addresses: ${error.message}`;
    }
}

function initLiveScanning() {
    $("scan-recent-btn")?.addEventListener("click", () => runLiveScan("recent"));
    $("monitor-mempool-btn")?.addEventListener("click", () => runLiveScan("mempool"));
}

async function runLiveScan(type) {
    toggle("live-scan-loading", true);
    toggle("live-scan-results", false);
    toggle("scan-recent-btn", false);
    toggle("monitor-mempool-btn", false);
    try {
        const data = type === "recent" ? await window.apiClient.autoScan() : await window.apiClient.monitorMempool();
        displayLiveScanResults(data, type);
    } catch (error) {
        displayLiveScanResults({ success: false, error: error.message }, type);
    } finally {
        toggle("live-scan-loading", false);
        const recent = $("scan-recent-btn");
        const mempool = $("monitor-mempool-btn");
        if (recent) recent.disabled = false;
        if (mempool) mempool.disabled = false;
    }
}

function displayLiveScanResults(data, type) {
    toggle("live-scan-results", true);
    const summary = $("scan-summary");
    const results = $("vulnerable-transactions");
    if (!summary || !results) return;
    results.replaceChildren();
    if (!data?.success) {
        summary.className = "alert alert-danger";
        summary.textContent = data?.error || "Scan failed";
        return;
    }
    const scanned = type === "recent" ? data.scanned_transactions : data.mempool_scanned;
    const found = type === "recent" ? data.weak_signatures_found : data.vulnerable_transactions;
    summary.className = `alert ${found ? "alert-warning" : "alert-success"}`;
    summary.textContent = `Scanned ${scanned ?? 0} transaction(s); ${found ?? 0} result(s).`;
    for (const item of data.results || []) {
        const card = document.createElement("div");
        card.className = "card mb-2";
        const body = document.createElement("div");
        body.className = "card-body";
        body.textContent = `Transaction: ${item.tx_id} | Findings: ${item.private_keys_found ?? 0}`;
        const button = document.createElement("button");
        button.className = "btn btn-sm btn-primary ms-2";
        button.textContent = "Analyze Details";
        button.addEventListener("click", () => goToTransaction(item.tx_id));
        body.appendChild(button);
        card.appendChild(body);
        results.appendChild(card);
    }
}

function initTransactionAnalysis() {
    const form = $("tx-analysis-form");
    if (!form) return;
    const txId = new URLSearchParams(window.location.search).get("tx");
    if (txId && $("tx-id")) {
        $("tx-id").value = txId;
        setTimeout(() => form.dispatchEvent(new Event("submit")), 100);
    }
}

function goToTransaction(txId) {
    window.location.href = `/transaction?tx=${encodeURIComponent(txId)}`;
}

function showPrivateKey(key) {
    if (confirm("Warning: you are about to view a private key. Continue?")) {
        alert(`Private key (hex):\n${key}`);
    }
}

function shortHex(value) {
    const text = String(value ?? "-");
    return text.length > 18 ? `${text.slice(0, 10)}...${text.slice(-6)}` : text;
}
