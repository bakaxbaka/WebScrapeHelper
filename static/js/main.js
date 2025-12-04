// Function to load known addresses from the API
function loadKnownAddresses() {
    const tbody = document.getElementById('known-addresses')?.querySelector('tbody');
    if (!tbody) return;

    // Clear existing rows
    tbody.innerHTML = '';

    // Add loading indicator
    const loadingRow = document.createElement('tr');
    loadingRow.innerHTML = `<td colspan="3" class="text-center">Loading addresses...</td>`;
    tbody.appendChild(loadingRow);

    // Fetch addresses from API
    fetch('/api/addresses/known')
        .then(response => {
            if (!response.ok) {
                throw new Error(`Failed to fetch addresses (${response.status})`);
            }
            return response.json();
        })
        .then(addresses => {
            // Clear loading indicator
            tbody.innerHTML = '';

            if (Array.isArray(addresses) && addresses.length > 0) {
                addresses.forEach(address => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td class="text-monospace">${address}</td>
                        <td><span class="badge bg-warning">Potentially Vulnerable</span></td>
                        <td>
                            <button class="btn btn-sm btn-primary" 
                                    onclick="window.location.href='/address?addr=${address}'">
                                Analyze
                            </button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            } else {
                const row = document.createElement('tr');
                row.innerHTML = `<td colspan="3" class="text-center">No addresses found</td>`;
                tbody.appendChild(row);
            }
        })
        .catch(error => {
            console.error('Failed to load known addresses:', error);
            tbody.innerHTML = '';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td colspan="3" class="text-center text-danger">
                    Error loading addresses: ${error.message}
                </td>
            `;
            tbody.appendChild(row);
        });
}

// Call the function when the page loads
document.addEventListener('DOMContentLoaded', function() {
    const addressesTable = document.getElementById('known-addresses');
    if (addressesTable) {
        loadKnownAddresses();
    }
});

// Main application logic
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing application...');
    // Initialize Bitcoin curve
    window.B = secp256k1();
    console.log('Bitcoin curve initialized');

    // Initialize forms
    initTransactionForm();
    initAddressForm();
    loadKnownAddresses();
    initLiveScanning();
});

function displayECDSAParameters(data, sig) {
    try {
        // Display curve parameters
        document.getElementById('param-p').textContent = B.ec.field.p.toString(16);
        document.getElementById('param-gx').textContent = B.G.x.uint().toString(16);
        document.getElementById('param-gy').textContent = B.G.y.uint().toString(16);
        document.getElementById('param-n').textContent = B.ec.order.p.toString(16);

        // Display transaction values if signature is available
        if (sig) {
            document.getElementById('param-m').textContent = sig.message;
            if (sig.px && sig.py) {
                document.getElementById('param-px').textContent = sig.px;
                document.getElementById('param-py').textContent = sig.py;
            }
        }
    } catch (error) {
        console.error('Error displaying ECDSA parameters:', error);
    }
}

function analyzeSignature(sig) {
    try {
        const r = BigInt('0x' + sig.r);
        const s = BigInt('0x' + sig.s);
        const m = BigInt('0x' + sig.message);

        // Check for weak signatures
        const weaknesses = [];

        // Check if s is in lower half of curve order
        if (s < (B.ec.order.p / 2n)) {
            weaknesses.push({
                type: 'low_s',
                details: 'Signature uses low S value',
                r: sig.r,
                s: sig.s
            });
        }

        return weaknesses;
    } catch (error) {
        console.error('Error analyzing signature:', error);
        return [];
    }
}

function initTransactionForm() {
    const form = document.getElementById('tx-analysis-form');
    if (!form) {
        console.error('Transaction form not found');
        return;
    }

    console.log('Transaction form initialized');
    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const txId = document.getElementById('tx-id').value;
        console.log('Analyzing transaction:', txId);

        if (!validateTransactionId(txId)) {
            showError('transaction', 'Invalid transaction ID format');
            return;
        }

        await analyzeTransaction(txId);
    });
}

function initAddressForm() {
    const form = document.getElementById('address-analysis-form');
    if (!form) {
        console.log('Address form not found on this page');
        return;
    }

    console.log('Address form initialized');
    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const address = document.getElementById('btc-address').value;
        console.log('Analyzing address:', address);

        if (!validateBitcoinAddress(address)) {
            showError('address', 'Invalid Bitcoin address format');
            return;
        }

        await analyzeAddress(address);
    });
}

async function analyzeTransaction(txId) {
    showLoading('analysis');
    hideError('transaction');

    try {
        console.log('Sending transaction analysis request:', txId);
        const response = await fetch('/api/analyze/transaction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ tx_id: txId })
        });

        const data = await response.json();
        console.log('Transaction analysis response:', data);

        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze transaction');
        }

        displayTransactionResults(data);
    } catch (error) {
        console.error('Transaction analysis error:', error);
        showError('transaction', error.message);
    } finally {
        hideLoading('analysis');
    }
}

async function analyzeAddress(address) {
    showLoading('address');
    hideError('address');

    try {
        console.log('Sending address analysis request:', address);
        const response = await fetch('/api/analyze/address', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ address: address })
        });

        const data = await response.json();
        console.log('Address analysis response:', data);

        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze address');
        }

        displayAddressResults(data);
    } catch (error) {
        console.error('Address analysis error:', error);
        showError('address', error.message);
    } finally {
        hideLoading('address');
    }
}

function displayTransactionResults(data) {
    console.log('Displaying transaction results:', data);

    const results = document.getElementById('analysis-results');
    if (!results) {
        console.error('Results container not found');
        return;
    }

    results.classList.remove('d-none');

    // Display ECDSA parameters
    if (data?.signatures?.[0]) {
        displayECDSAParameters(data, data.signatures[0]);
    }

    // Display analysis results
    document.getElementById('result-txid').textContent = data?.tx_id || 'N/A';
    document.getElementById('result-sigs').textContent = data?.signatures_analyzed || 0;
    document.getElementById('result-weak').textContent = (data?.weak_signatures || []).length;
    document.getElementById('result-keys').textContent = data?.private_keys_found || 0;

    const tableBody = document.getElementById('weak-sigs-table');
    if (!tableBody) {
        console.error('Weak signatures table not found');
        return;
    }

    tableBody.innerHTML = '';

    if (data?.weak_signatures?.length > 0) {
        data.weak_signatures.forEach(sig => {
            const row = document.createElement('tr');
            const isPrivateKey = sig.type === 'recovered_key';

            row.innerHTML = `
                <td><span class="badge bg-danger">${sig?.type || 'Unknown'}</span></td>
                <td class="text-monospace">${sig?.details || 'N/A'}</td>
                <td>
                    ${isPrivateKey ? `
                        <button class="btn btn-sm btn-warning" onclick="showPrivateKey('${sig.private_key}')">
                            <i class="fas fa-key"></i> View Key
                        </button>
                    ` : `
                        <button class="btn btn-sm btn-info" onclick="showSignatureDetails('${sig?.r || ''}', '${sig?.type || ''}', ${JSON.stringify(sig).replace(/"/g, '&quot;')})">
                            <i class="fas fa-info-circle"></i> Details
                        </button>
                    `}
                </td>
            `;
            tableBody.appendChild(row);
        });

        // Show recovered keys section if there are any
        const recoveredKeys = data.weak_signatures.filter(sig => sig.type === 'recovered_key');
        const keysSection = document.getElementById('recovered-keys');
        const keysTable = document.getElementById('private-keys-table');

        if (recoveredKeys.length > 0) {
            keysSection.classList.remove('d-none');
            keysTable.innerHTML = '';

            recoveredKeys.forEach(key => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="text-monospace">${key.private_key}</td>
                    <td class="text-monospace">${key.k || 'N/A'}</td>
                    <td>Hex Format (32 bytes)</td>
                `;
                keysTable.appendChild(row);
            });
        } else {
            keysSection.classList.add('d-none');
        }
    } else {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="3" class="text-center">No weak signatures found</td>';
        tableBody.appendChild(row);
    }
}

function displayAddressResults(data) {
    console.log('Displaying address results:', data);

    const results = document.getElementById('address-results');
    if (!results) {
        console.error('Results container not found');
        return;
    }

    results.classList.remove('d-none');

    // Safe access to data properties
    document.getElementById('result-address').textContent = data?.address || 'N/A';
    const txsAnalyzed = data?.transactions_analyzed || 0;
    const totalTxs = data?.total_transactions || txsAnalyzed;
    document.getElementById('result-txs').textContent = totalTxs > 50 ? `${txsAnalyzed} (limited to first 50 of ${totalTxs})` : txsAnalyzed;
    document.getElementById('result-weak').textContent = (data?.weak_signatures || []).length;

    const tableBody = document.getElementById('address-weak-sigs');
    if (!tableBody) {
        console.error('Weak signatures table not found');
        return;
    }

    tableBody.innerHTML = '';

    if (data?.weak_signatures?.length > 0) {
        data.weak_signatures.forEach(sig => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="text-monospace">${sig?.tx_id || 'N/A'}</td>
                <td><span class="badge bg-danger">${sig?.type || 'Unknown'}</span></td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="showSignatureDetails('${sig?.r || ''}', '${sig?.type || ''}', ${JSON.stringify(sig).replace(/"/g, '&quot;')})">
                        <i class="fas fa-info-circle"></i> View Details
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    } else {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="3" class="text-center">No weak signatures found</td>';
        tableBody.appendChild(row);
    }

    const relatedAddresses = document.getElementById('related-addresses');
    if (!relatedAddresses) {
        console.error('Related addresses container not found');
        return;
    }

    relatedAddresses.innerHTML = '';

    if (data?.related_addresses?.length > 0) {
        data.related_addresses.forEach(addr => {
            const div = document.createElement('div');
            div.className = 'alert alert-info';
            div.textContent = addr;
            relatedAddresses.appendChild(div);
        });
    } else {
        relatedAddresses.innerHTML = '<p>No related addresses found</p>';
    }
}

function loadKnownAddresses() {
    console.log('Fetching known addresses');
    fetch('/api/addresses/known')
        .then(response => response.json())
        .then(addresses => {
            console.log('Received known addresses:', addresses);
            const addressList = document.getElementById('known-addresses-list');
            if (addressList) {
                addressList.innerHTML = addresses.map(addr => 
                    `<li class="list-group-item d-flex justify-content-between align-items-center">
                        <code>${addr}</code>
                        <button class="btn btn-sm btn-outline-primary" onclick="analyzeKnownAddress('${addr}')">
                            <i class="fas fa-search"></i> Analyze
                        </button>
                    </li>`
                ).join('');
            }
        })
        .catch(error => console.error('Error loading known addresses:', error));
}

function showLoading(type) {
    const element = document.getElementById(`${type}-loading`);
    if (element) {
        element.classList.remove('d-none');
    }
}

function hideLoading(type) {
    const element = document.getElementById(`${type}-loading`);
    if (element) {
        element.classList.add('d-none');
    }
}

function showError(type, message) {
    const error = document.getElementById(`${type}-error`);
    if (error) {
        error.textContent = message;
        error.classList.remove('d-none');
    }
}

function hideError(type) {
    const error = document.getElementById(`${type}-error`);
    if (error) {
        error.classList.add('d-none');
    }
}

function showPrivateKey(key) {
    if (confirm('Warning: You are about to view a private key. Make sure no one else can see your screen. Continue?')) {
        alert(`Private Key (hex):\n${key}\n\nWarning: Store this securely and never share it with anyone.`);
    }
}

function showSignatureDetails(r, type, sigData) {
    try {
        const sig = typeof sigData === 'string' ? JSON.parse(sigData.replace(/&quot;/g, '"')) : sigData;

        let detailsHTML = `
            <div class="modal fade" id="signatureModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Signature Vulnerability Details</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <h6 class="text-danger">Vulnerability Type: ${type.toUpperCase()}</h6>
                            <hr>

                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Signature Components:</h6>
                                    <p><strong>r value:</strong><br><code class="text-break">${sig.r || 'N/A'}</code></p>
                                    <p><strong>s value:</strong><br><code class="text-break">${sig.s || 'N/A'}</code></p>
                                    <p><strong>Message Hash:</strong><br><code class="text-break">${sig.message || 'N/A'}</code></p>
                                </div>
                                <div class="col-md-6">
                                    <h6>Analysis Details:</h6>
                                    <p><strong>Issue:</strong> ${sig.details || 'N/A'}</p>
                                    ${sig.tx_id ? `<p><strong>Transaction:</strong><br><code>${sig.tx_id}</code></p>` : ''}
                                    ${sig.private_key ? `<p><strong>Recovered Key:</strong><br><code class="text-success">${sig.private_key}</code></p>` : ''}
                                </div>
                            </div>

                            ${type === 'reused_r' ? `
                                <hr>
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-exclamation-triangle"></i> Nonce Reuse Vulnerability</h6>
                                    <p>This signature reuses the same r value (nonce) as ${sig.reuse_count || 'multiple'} other signatures. This allows private key recovery using the formula:</p>
                                    <p><strong>k = (z₁ - z₂) / (s₁ - s₂) mod n</strong></p>
                                    <p><strong>x = (s × k - z) / r mod n</strong></p>
                                    <p>Where k is the nonce and x is the private key.</p>
                                    ${sig.all_signatures && sig.all_signatures.length > 1 ? `
                                        <hr>
                                        <h6>All Signatures with this R value:</h6>
                                        <div class="table-responsive" style="max-height: 300px; overflow-y: auto;">
                                            <table class="table table-sm">
                                                <thead>
                                                    <tr>
                                                        <th>S Value</th>
                                                        <th>Message Hash</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    ${sig.all_signatures.map(s => `
                                                        <tr>
                                                            <td><code class="small">${s.s?.substring(0, 16)}...</code></td>
                                                            <td><code class="small">${s.message?.substring(0, 16)}...</code></td>
                                                        </tr>
                                                    `).join('')}
                                                </tbody>
                                            </table>
                                        </div>
                                    ` : ''}
                                </div>
                            ` : ''}

                            ${type === 'low_s' ? `
                                <hr>
                                <div class="alert alert-info">
                                    <h6><i class="fas fa-info-circle"></i> Low S Value</h6>
                                    <p>This signature uses a low s value, which is a good security practice but can indicate implementation patterns.</p>
                                </div>
                            ` : ''}

                            <hr>
                            <h6>ECDSA Parameters:</h6>
                            <div class="row">
                                <div class="col-md-6">
                                    <p><strong>Curve:</strong> secp256k1</p>
                                    <p><strong>Prime (p):</strong><br><code class="small">FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F</code></p>
                                    <p><strong>Order (n):</strong><br><code class="small">FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141</code></p>
                                </div>
                                <div class="col-md-6">
                                    <p><strong>Generator Point G:</strong></p>
                                    <p><strong>Gx:</strong><br><code class="small">79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798</code></p>
                                    <p><strong>Gy:</strong><br><code class="small">483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8</code></p>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            ${sig.private_key ? `
                                <button type="button" class="btn btn-warning" onclick="copyToClipboard('${sig.private_key}')">
                                    <i class="fas fa-copy"></i> Copy Private Key
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if present
        const existingModal = document.getElementById('signatureModal');
        if (existingModal) {
            existingModal.remove();
        }

        // Add modal to body
        document.body.insertAdjacentHTML('beforeend', detailsHTML);

        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('signatureModal'));
        modal.show();

    } catch (error) {
        console.error('Error showing signature details:', error);
        alert('Error displaying signature details. Check console for more information.');
    }
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Private key copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy: ', err);
            fallbackCopyTextToClipboard(text);
        });
    } else {
        fallbackCopyTextToClipboard(text);
    }
}

function fallbackCopyTextToClipboard(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        document.execCommand('copy');
        alert('Private key copied to clipboard!');
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
        alert('Failed to copy to clipboard. Please copy manually.');
    }

    document.body.removeChild(textArea);
}

function initLiveScanning() {
    const scanRecentBtn = document.getElementById('scan-recent-btn');
    const monitorMempoolBtn = document.getElementById('monitor-mempool-btn');

    if (scanRecentBtn) {
        scanRecentBtn.addEventListener('click', scanRecentBlocks);
    }

    if (monitorMempoolBtn) {
        monitorMempoolBtn.addEventListener('click', monitorMempool);
    }
}

function showLiveScanLoading() {
    document.getElementById('live-scan-loading').classList.remove('d-none');
    document.getElementById('live-scan-results').classList.add('d-none');
    document.getElementById('scan-recent-btn').disabled = true;
    document.getElementById('monitor-mempool-btn').disabled = true;
}

function hideLiveScanLoading() {
    document.getElementById('live-scan-loading').classList.add('d-none');
    document.getElementById('scan-recent-btn').disabled = false;
    document.getElementById('monitor-mempool-btn').disabled = false;
}

function displayLiveScanResults(data, scanType) {
    const summaryDiv = document.getElementById('scan-summary');
    const resultsDiv = document.getElementById('vulnerable-transactions');

    if (data.success) {
        const scannedCount = scanType === 'recent' ? data.scanned_transactions : data.mempool_scanned;
        const foundCount = scanType === 'recent' ? data.weak_signatures_found : data.vulnerable_transactions;

        summaryDiv.innerHTML = `
            <h6>Scan Complete</h6>
            <p><strong>Transactions Scanned:</strong> ${scannedCount}</p>
            <p><strong>Vulnerable Signatures Found:</strong> ${foundCount}</p>
            ${scanType === 'recent' ? `<p><strong>Block Hash:</strong> <code>${data.block_hash || 'N/A'}</code></p>` : ''}
        `;

        if (foundCount > 0) {
            summaryDiv.className = 'alert alert-warning';
            resultsDiv.innerHTML = data.results.map(result => `
                <div class="card mb-2">
                    <div class="card-body">
                        <h6 class="card-title">Transaction: <code>${result.tx_id}</code></h6>
                        <p><strong>Private Keys Found:</strong> ${result.private_keys_found}</p>
                        <p><strong>Weak Signatures:</strong> ${result.weak_signatures ? result.weak_signatures.length : 0}</p>
                        ${scanType === 'mempool' ? `
                            <p><strong>Fee:</strong> ${result.fee} satoshis</p>
                            <p><strong>Size:</strong> ${result.size} bytes</p>
                            <p><strong>Timestamp:</strong> ${new Date(result.timestamp * 1000).toLocaleString()}</p>
                        ` : ''}
                        <button class="btn btn-sm btn-primary" onclick="analyzeTransaction('${result.tx_id}')">
                            <i class="fas fa-microscope"></i> Analyze Details
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            summaryDiv.className = 'alert alert-success';
            resultsDiv.innerHTML = '<p class="text-muted">No vulnerable signatures found in scanned transactions.</p>';
        }
    } else {
        summaryDiv.className = 'alert alert-danger';
        summaryDiv.innerHTML = `<h6>Scan Failed</h6><p>Error: ${data.error}</p>`;
        resultsDiv.innerHTML = '';
    }

    document.getElementById('live-scan-results').classList.remove('d-none');
}

function scanRecentBlocks() {
    showLiveScanLoading();

    fetch('/api/auto-scan')
        .then(response => response.json())
        .then(data => {
            hideLiveScanLoading();
            displayLiveScanResults(data, 'recent');
        })
        .catch(error => {
            console.error('Error scanning recent blocks:', error);
            hideLiveScanLoading();
            displayLiveScanResults({
                success: false,
                error: 'Failed to scan recent blocks: ' + error.message
            }, 'recent');
        });
}

function monitorMempool() {
    showLiveScanLoading();

    fetch('/api/monitor-mempool')
        .then(response => response.json())
        .then(data => {
            hideLiveScanLoading();
            displayLiveScanResults(data, 'mempool');
        })
        .catch(error => {
            console.error('Error monitoring mempool:', error);
            hideLiveScanLoading();
            displayLiveScanResults({
                success: false,
                error: 'Failed to monitor mempool: ' + error.message
            }, 'mempool');
        });
}

function initTransactionAnalysis() {
    const txForm = document.getElementById('transaction-form');
    if (!txForm) {
        console.log('Transaction form not found');
        return;
    }

    // Check for pre-filled transaction ID from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const txId = urlParams.get('tx');
    if (txId) {
        const txInput = document.getElementById('tx-id');
        if (txInput) {
            txInput.value = txId;
            // Auto-submit the form
            setTimeout(() => txForm.dispatchEvent(new Event('submit')), 500);
        }
    }
}

function analyzeTransaction(txId) {
    // Navigate to transaction analysis page with pre-filled ID
    window.location.href = `/transaction?tx=${txId}`;
}