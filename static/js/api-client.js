"use strict";

/**
 * Single frontend boundary for backend calls.
 * UI modules should call window.apiClient instead of constructing fetch()
 * requests themselves.
 */
(function (global) {
    const API_PREFIX = "/api";

    async function request(path, options = {}) {
        const response = await fetch(`${API_PREFIX}${path}`, {
            ...options,
            headers: {
                Accept: "application/json",
                ...(options.body ? { "Content-Type": "application/json" } : {}),
                ...(options.headers || {}),
            },
        });

        const contentType = response.headers.get("content-type") || "";
        const data = contentType.includes("application/json")
            ? await response.json()
            : await response.text();

        if (!response.ok) {
            const message = typeof data === "object" && data?.error
                ? data.error
                : `Request failed (${response.status})`;
            const error = new Error(message);
            error.status = response.status;
            error.data = data;
            throw error;
        }
        return data;
    }

    function post(path, payload) {
        return request(path, {
            method: "POST",
            body: JSON.stringify(payload),
        });
    }

    global.apiClient = Object.freeze({
        health: () => request("/health"),
        knownAddresses: () => request("/addresses/known"),
        analyzeTransaction: (txId) => post("/analyze/transaction", { tx_id: txId }),
        analyzeAddress: (address, maxTxs = 500) => post("/analyze/address", { address, max_txs: maxTxs }),
        scanAddress: (address, maxTxs = 500) => post("/scan/address", { address, max_txs: maxTxs }),
        analyzeECDSA: (payload) => post("/analyze/ecdsa", payload),
        calculateNonce: (payload) => post("/calculate/nonce", payload),
        calculateNonceFromPrivateKey: (payload) => post("/calculate/nonce-from-private-key", payload),
        recoverWithKnownNonce: (payload) => post("/recover/low-s-with-nonce", payload),
        analyzeMalleability: (payload) => post("/recover/malleability-signatures", payload),
        autoScan: () => request("/auto-scan"),
        monitorMempool: () => request("/monitor-mempool"),
    });
})(window);
