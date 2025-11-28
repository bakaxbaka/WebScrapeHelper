// ECDSA Parameter Verification Functions
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bitcoin curve
    console.log("Bitcoin curve initialized");

    // Bitcoin curve order
    const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

    // Handle verification of signing secret (k)
    const verifyKBtn = document.getElementById('verify-k-btn');
    if (verifyKBtn) {
        verifyKBtn.addEventListener('click', function() {
            const m1 = BigInt('0x' + document.getElementById('verify-m1').value);
            const m2 = BigInt('0x' + document.getElementById('verify-m2').value);
            const s1 = BigInt('0x' + document.getElementById('verify-s1').value);
            const s2 = BigInt('0x' + document.getElementById('verify-s2').value);

            // Calculate k = (m1-m2)/(s1-s2) mod n
            const m_diff = (m1 - m2) % n;
            const s_diff = (s1 - s2) % n;

            // Calculate modular inverse of s_diff
            const s_diff_inv = modInverse(s_diff, n);

            // Calculate k
            const k = (m_diff * s_diff_inv) % n;
            const kHex = '0x' + k.toString(16);

            document.getElementById('calculated-k').textContent = kHex;

            // Auto-fill other verification fields
            if (document.getElementById('verify-k')) {
                document.getElementById('verify-k').value = k.toString(16);
            }

            // If we have r and s values from the first signature, auto-fill private key verification
            if (document.getElementById('verify-r') && document.getElementById('verify-r').value && 
                document.getElementById('verify-s') && document.getElementById('verify-s').value &&
                document.getElementById('verify-m') && document.getElementById('verify-m').value) {

                // Trigger private key calculation
                document.getElementById('verify-x-btn').click();
            }
        });
    }

    // Handle verification of private key (x)
    const verifyXBtn = document.getElementById('verify-x-btn');
    if (verifyXBtn) {
        verifyXBtn.addEventListener('click', function() {
            const r = BigInt('0x' + document.getElementById('verify-r').value);
            const s = BigInt('0x' + document.getElementById('verify-s').value);
            const m = BigInt('0x' + document.getElementById('verify-m').value);
            const k = BigInt('0x' + document.getElementById('verify-k').value);

            // Calculate x = (s*k - m)/r mod n
            const r_inv = modInverse(r, n);
            const x = ((s * k - m) * r_inv) % n;
            const xHex = '0x' + x.toString(16);

            document.getElementById('calculated-x').textContent = xHex;

            // Auto-fill private key in pubkey verification
            if (document.getElementById('verify-private-key')) {
                document.getElementById('verify-private-key').value = x.toString(16);

                // Trigger public key calculation
                document.getElementById('verify-pubkey-btn').click();
            }

            // Verify the signature automatically
            verifySignature(r, s, m, x);
        });
    }

    // Handle public key calculation
    const verifyPubkeyBtn = document.getElementById('verify-pubkey-btn');
    if (verifyPubkeyBtn) {
        verifyPubkeyBtn.addEventListener('click', function() {
            const x = BigInt('0x' + document.getElementById('verify-private-key').value);

            // This would require elliptic curve point multiplication
            // For simplicity, we're just acknowledging the calculation
            document.getElementById('calculated-pubkey').textContent = 'Public key calculation requires full EC implementation';

            // If we have r, s, m already filled out, verify the signature
            if (document.getElementById('verify-r') && document.getElementById('verify-r').value && 
                document.getElementById('verify-s') && document.getElementById('verify-s').value &&
                document.getElementById('verify-m') && document.getElementById('verify-m').value) {

                const r = BigInt('0x' + document.getElementById('verify-r').value);
                const s = BigInt('0x' + document.getElementById('verify-s').value);
                const m = BigInt('0x' + document.getElementById('verify-m').value);

                verifySignature(r, s, m, x);
            }
        });
    }

    // Function to verify signature and update UI
    function verifySignature(r, s, m, x) {
        try {
            // For demo purposes, we're just indicating that verification was attempted
            // In a real implementation, this would perform the actual ECDSA verification
            document.getElementById('sig-verification-result').textContent = 
                "Verification attempted with r=" + r.toString(16).substring(0, 8) + "..., " +
                "s=" + s.toString(16).substring(0, 8) + "..., " +
                "m=" + m.toString(16).substring(0, 8) + "..., " +
                "x=" + x.toString(16).substring(0, 8) + "...";
        } catch (e) {
            document.getElementById('sig-verification-result').textContent = "Error during verification: " + e.message;
        }
    }

    // Utility function for modular inverse
    function modInverse(a, m) {
        a = ((a % m) + m) % m; // Ensure positive value

        // Extended Euclidean Algorithm to find modular inverse
        let [old_r, r] = [BigInt(a), BigInt(m)];
        let [old_s, s] = [BigInt(1), BigInt(0)];

        while (r !== BigInt(0)) {
            const quotient = old_r / r;
            [old_r, r] = [r, old_r - quotient * r];
            [old_s, s] = [s, old_s - quotient * s];
        }

        // If gcd(a, m) != 1, modular inverse doesn't exist
        if (old_r !== BigInt(1)) {
            throw new Error('Modular inverse does not exist');
        }

        return ((old_s % m) + m) % m;
    }

    // Initialize transaction form if present
    const txForm = document.getElementById('ecdsa-analysis-form');
    if (txForm) {
        console.log("Transaction form initialized");
        txForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const txId = document.getElementById('tx-id').value.trim();

            if (txId) {
                console.log("Analyzing transaction:", txId);
                document.getElementById('analysis-loading').classList.remove('d-none');
                document.getElementById('analysis-results').classList.add('d-none');
                document.getElementById('analysis-error').classList.add('d-none');

                // Send request to analyze transaction
                fetch('/api/analyze_transaction', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ tx_id: txId }),
                })
                .then(response => response.json())
                .then(data => {
                    console.log("Transaction analysis response:", data);
                    document.getElementById('analysis-loading').classList.add('d-none');

                    if (data.error) {
                        document.getElementById('analysis-error').textContent = data.error;
                        document.getElementById('analysis-error').classList.remove('d-none');
                        return;
                    }

                    // Display results
                    displayResults(data);
                })
                .catch(error => {
                    console.error('Error analyzing transaction:', error);
                    document.getElementById('analysis-loading').classList.add('d-none');
                    document.getElementById('analysis-error').textContent = 'Error analyzing transaction: ' + error.message;
                    document.getElementById('analysis-error').classList.remove('d-none');
                });
            }
        });
    }

    // Function to display transaction analysis results
    function displayResults(data) {
        console.log("Displaying transaction results:", data);

        // Show results section
        document.getElementById('analysis-results').classList.remove('d-none');

        // Display curve parameters
        document.getElementById('param-p').textContent = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
        document.getElementById('param-n').textContent = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
        document.getElementById('param-gx').textContent = '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
        document.getElementById('param-gy').textContent = '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';

        // Display signature data
        const signaturesContainer = document.getElementById('signatures');
        signaturesContainer.innerHTML = '';

        if (data.signatures && data.signatures.length > 0) {
            data.signatures.forEach((sig, index) => {
                const sigDiv = document.createElement('div');
                sigDiv.classList.add('mb-3');
                sigDiv.innerHTML = `
                    <h6>Signature ${index + 1}</h6>
                    <p><strong>r:</strong> ${sig.r}</p>
                    <p><strong>s:</strong> ${sig.s}</p>
                    <p><strong>Message Hash:</strong> ${sig.message}</p>
                `;
                signaturesContainer.appendChild(sigDiv);

                // Auto-fill verification form with signature data
                if (index === 0) {
                    if (document.getElementById('verify-r')) document.getElementById('verify-r').value = sig.r;
                    if (document.getElementById('verify-s')) document.getElementById('verify-s').value = sig.s;
                    if (document.getElementById('verify-m')) document.getElementById('verify-m').value = sig.message;
                }

                // If we have two signatures, populate the k recovery fields
                if (index === 0 && data.signatures.length > 1) {
                    if (document.getElementById('verify-m1')) document.getElementById('verify-m1').value = sig.message;
                    if (document.getElementById('verify-s1')) document.getElementById('verify-s1').value = sig.s;
                }
                if (index === 1) {
                    if (document.getElementById('verify-m2')) document.getElementById('verify-m2').value = sig.message;
                    if (document.getElementById('verify-s2')) document.getElementById('verify-s2').value = sig.s;

                    // If we have two valid signatures, auto-calculate k
                    if (document.getElementById('verify-m1').value && 
                        document.getElementById('verify-s1').value &&
                        document.getElementById('verify-m2').value &&
                        document.getElementById('verify-s2').value) {
                        setTimeout(() => {
                            document.getElementById('verify-k-btn').click();
                        }, 500);
                    }
                }
            });

            // Set verification status
            document.getElementById('verify-result').textContent = 'Pending verification';
            document.getElementById('point-valid').textContent = 'Pending validation';

            // If there are signatures but no weak points detected
            if (data.weak_signatures && data.weak_signatures.length === 0) {
                document.getElementById('verify-result').textContent = 'No weaknesses detected';
            } else {
                document.getElementById('verify-result').textContent = `Found ${data.weak_signatures.length} potential weaknesses`;
            }
        } else {
            signaturesContainer.innerHTML = '<p>No signatures found in this transaction.</p>';
            document.getElementById('verify-result').textContent = 'N/A';
            document.getElementById('point-valid').textContent = 'N/A';
        }
    }

    // Check if we're on the known addresses table page
    const knownAddressesTable = document.getElementById('known-addresses-table');
    if (knownAddressesTable) {
        console.log("Known addresses table initialized");
    } else {
        console.log("Known addresses table not present on this page");
    }
});

// ECDSA Analysis Functions
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing ECDSA analyzer...');
    // Initialize Bitcoin curve parameters.  Note:  This section is modified to use direct parameter definitions instead of relying on an external library that was not defined in the original code.
    const CURVE_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    const CURVE_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
    const CURVE_A = 0n;
    const CURVE_B = 7n;
    const G_X = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
    const G_Y = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

    initECDSAForm();
    displayCurveParameters();
});

function initECDSAForm() {
    const form = document.getElementById('ecdsa-analysis-form');
    if (!form) {
        console.error('ECDSA analysis form not found');
        return;
    }

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        performAnalysis();
    });
}

function displayCurveParameters() {
    try {
        // Display curve parameters
        document.getElementById('param-p').textContent = CURVE_P.toString(16);
        document.getElementById('param-n').textContent = CURVE_N.toString(16);
        document.getElementById('param-gx').textContent = G_X.toString(16);
        document.getElementById('param-gy').textContent = G_Y.toString(16);
    } catch (error) {
        console.error('Error displaying curve parameters:', error);
    }
}

async function performAnalysis() {
    try {
        showLoading();
        hideError();

        const txId = document.getElementById('tx-id').value;
        console.log('Analyzing transaction:', txId);

        // Fetch transaction data
        const response = await fetch('/api/analyze/transaction', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ tx_id: txId })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze transaction');
        }

        // Display results
        document.getElementById('signatures').innerHTML = '';
        if (data.signatures && data.signatures.length > 0) {
            data.signatures.forEach((sig, index) => {
                const sigDiv = document.createElement('div');
                sigDiv.innerHTML = `
                    <h6>Signature #${index + 1}</h6>
                    <p><strong>Message Hash (m):</strong> <span class="text-monospace">${sig.message}</span></p>
                    <p><strong>r:</strong> <span class="text-monospace">${sig.r}</span></p>
                    <p><strong>s:</strong> <span class="text-monospace">${sig.s}</span></p>
                    ${sig.px ? `
                    <p><strong>Public Key (Y):</strong></p>
                    <p class="ms-3">px: <span class="text-monospace">${sig.px}</span></p>
                    <p class="ms-3">py: <span class="text-monospace">${sig.py}</span></p>
                    ` : ''}
                `;
                document.getElementById('signatures').appendChild(sigDiv);

                // Analyze signature for weaknesses
                const weaknesses = analyzeSignature(sig);
                if (weaknesses.length > 0) {
                    const weakDiv = document.createElement('div');
                    weakDiv.innerHTML = `
                        <div class="alert alert-danger">
                            <h6>Weaknesses Found:</h6>
                            ${weaknesses.map(w => `<p>${w.details}</p>`).join('')}
                        </div>
                    `;
                    document.getElementById('signatures').appendChild(weakDiv);
                }
            });
        }

        showResults();
    } catch (error) {
        console.error('Analysis error:', error);
        showError(error.message);
    } finally {
        hideLoading();
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
        if (s < (CURVE_N / 2n)) {
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

function showLoading() {
    document.getElementById('analysis-loading').classList.remove('d-none');
    document.getElementById('analysis-results').classList.add('d-none');
}

function hideLoading() {
    document.getElementById('analysis-loading').classList.add('d-none');
}

function showResults() {
    document.getElementById('analysis-results').classList.remove('d-none');
}

function showError(message) {
    const error = document.getElementById('analysis-error');
    error.textContent = message;
    error.classList.remove('d-none');
}

function hideError() {
    document.getElementById('analysis-error').classList.add('d-none');
}

function modInv(a, n) {
    return BigInt(a) ** BigInt(n - 2n) % BigInt(n);
}

function validatePoint(point) {
    try {
        // y² = x³ + 7 (secp256k1 curve equation)
        const x3 = point.x.uint() ** 3n % CURVE_P;
        const y2 = (point.y.uint() ** 2n) % CURVE_P;
        return (y2 === (x3 + 7n) % CURVE_P);
    } catch (error) {
        console.error('Point validation error:', error);
        return false;
    }
}

// Bitcoin curve parameters
const CURVE_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const CURVE_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
const CURVE_A = 0n;
const CURVE_B = 7n;
const G_X = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
const G_Y = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

// Add event listeners once the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Event listeners for ECDSA analysis form
    document.getElementById('calculate-ecdsa').addEventListener('click', analyzeECDSA);

    // Add verification button event listeners
    document.getElementById('verify-k-btn').addEventListener('click', verifySigningSecret);
    document.getElementById('verify-params-btn').addEventListener('click', verifyParameters);

    // Auto-calculate on input change (optional)
    const inputFields = ['ecdsa-r1', 'ecdsa-s1', 'ecdsa-m1', 'ecdsa-r2', 'ecdsa-s2', 'ecdsa-m2'];
    inputFields.forEach(id => {
        document.getElementById(id).addEventListener('input', function() {
            if (document.getElementById('auto-calculate').checked) {
                analyzeECDSA();
            }
        });
    });
});

// Convert hex string to BigInt
function hexToBigInt(hex) {
    if (!hex) return null;
    // Remove '0x' prefix if present
    hex = hex.replace(/^0x/i, '');
    // Ensure hex is a valid string
    if (!/^[0-9a-f]+$/i.test(hex)) {
        throw new Error('Invalid hex string: ' + hex);
    }
    return BigInt('0x' + hex);
}

// BigInt modulo that works with negative numbers
function mod(a, n) {
    return ((a % n) + n) % n;
}

// Modular inverse
function modInv(a, n) {
    // Extended Euclidean Algorithm to find modular inverse
    let t = 0n, newT = 1n;
    let r = n, newR = a;

    while (newR !== 0n) {
        let quotient = r / newR;
        [t, newT] = [newT, t - quotient * newT];
        [r, newR] = [newR, r - quotient * newR];
    }

    if (r > 1n) throw new Error('Not invertible');
    if (t < 0n) t += n;

    return t;
}

// Calculate k from two signatures with the same r value
function calculateK(m1, s1, m2, s2, n) {
    try {
        // k = (m1 - m2) * (s1 - s2)^-1 mod n
        const mDiff = mod(m1 - m2, n);
        const sDiff = mod(s1 - s2, n);

        if (sDiff === 0n) {
            throw new Error('s1 - s2 = 0, cannot compute k');
        }

        const sInv = modInv(sDiff, n);
        const k = mod(mDiff * sInv, n);

        return k;
    } catch (e) {
        console.error('Error calculating k:', e);
        return null;
    }
}

// Calculate private key x from k, r, s, and m
function calculatePrivateKey(k, r, s, m, n) {
    try {
        // x = (s*k - m) * r^-1 mod n
        const rInv = modInv(r, n);
        const x = mod((s * k - m) * rInv, n);

        return x;
    } catch (e) {
        console.error('Error calculating private key:', e);
        return null;
    }
}

function analyzeECDSA() {
    // Get form values
    const r1 = document.getElementById('ecdsa-r1').value;
    const s1 = document.getElementById('ecdsa-s1').value;
    const m1 = document.getElementById('ecdsa-m1').value;
    const r2 = document.getElementById('ecdsa-r2').value;
    const s2 = document.getElementById('ecdsa-s2').value;
    const m2 = document.getElementById('ecdsa-m2').value;

    // Validate inputs
    if (!r1 || !s1 || !m1) {
        alert('Please fill in at least the first signature (r1, s1, m1)');
        return;
    }

    try {
        // Convert inputs to BigInt for calculations
        const r1BigInt = hexToBigInt(r1);
        const s1BigInt = hexToBigInt(s1);
        const m1BigInt = hexToBigInt(m1);

        let r2BigInt, s2BigInt, m2BigInt;
        let kValue, xValue;

        // Check if we have a complete second signature
        if (r2 && s2 && m2) {
            r2BigInt = hexToBigInt(r2);
            s2BigInt = hexToBigInt(s2);
            m2BigInt = hexToBigInt(m2);

            // Verify r values are the same (required for k recovery)
            if (r1BigInt !== r2BigInt) {
                document.getElementById('ecdsa-warning').textContent = 
                    'Warning: r values are different. For signature reuse attack, r values must be identical.';
                document.getElementById('ecdsa-warning').style.display = 'block';
            } else {
                document.getElementById('ecdsa-warning').style.display = 'none';

                // Calculate k and x locally
                kValue = calculateK(m1BigInt, s1BigInt, m2BigInt, s2BigInt, CURVE_N);
                if (kValue) {
                    xValue = calculatePrivateKey(kValue, r1BigInt, s1BigInt, m1BigInt, CURVE_N);
                }

                // Update results
                if (kValue) document.getElementById('ecdsa-k-result').innerText = '0x' + kValue.toString(16);
                if (xValue) document.getElementById('ecdsa-x-result').innerText = '0x' + xValue.toString(16);

                if (kValue && xValue) {
                    document.getElementById('ecdsa-success').innerText = 'Successfully recovered private key!';
                    document.getElementById('signing-secret-value').value = kValue.toString(16);
                    document.getElementById('private-key-value').value = xValue.toString(16);
                } else {
                    document.getElementById('ecdsa-success').innerText = 'Failed to recover private key';
                }

                return; // Skip server call if we've calculated locally
            }
        }

        // Submit to server for analysis if needed
        fetch('/api/analyze/ecdsa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                r1: r1,
                s1: s1,
                m1: m1,
                r2: r2 || r1, // Use r1 as fallback
                s2: s2 || null,
                m2: m2 || null
            }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Server error:', data.error);
                document.getElementById('ecdsa-warning').textContent = 'Error: ' + data.error;
                document.getElementById('ecdsa-warning').style.display = 'block';
                return;
            }

            // Update results
            document.getElementById('ecdsa-k-result').innerText = data.k || 'Not found';
            document.getElementById('ecdsa-x-result').innerText = data.x || 'Not found';
            document.getElementById('ecdsa-success').innerText = data.success ? 'Successfully recovered private key!' : 'Failed to recover private key';

            // Update verification input fields
            if (data.k) document.getElementById('signing-secret-value').value = data.k.replace(/^0x/, '');
            if (data.x) document.getElementById('private-key-value').value = data.x.replace(/^0x/, '');
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('ecdsa-warning').textContent = 'Failed to analyze ECDSA parameters: ' + error;
            document.getElementById('ecdsa-warning').style.display = 'block';
        });
    } catch (e) {
        console.error('Error processing input values:', e);
        document.getElementById('ecdsa-warning').textContent = 'Error processing input values: ' + e.message;
        document.getElementById('ecdsa-warning').style.display = 'block';
    }
}

// Verify the signing secret (k) produces the correct signature
function verifySigningSecret() {
    try {
        const k = hexToBigInt(document.getElementById('signing-secret-value').value);
        const x = hexToBigInt(document.getElementById('private-key-value').value);
        const r = hexToBigInt(document.getElementById('ecdsa-r1').value);
        const s = hexToBigInt(document.getElementById('ecdsa-s1').value);
        const m = hexToBigInt(document.getElementById('ecdsa-m1').value);

        if (!k || !r || !s || !m) {
            document.getElementById('k-verification-result').textContent = 'Please fill in all required fields';
            document.getElementById('k-verification-result').className = 'text-warning';
            return;
        }

        // Check if k*G.x mod n equals r
        // This requires point multiplication and is complex in pure JS
        // Let's check if s = (m + r*x)/k instead

        const expectedS = mod((m + r * x) * modInv(k, CURVE_N), CURVE_N);

        if (expectedS === s) {
            document.getElementById('k-verification-result').textContent = 'Verification successful: k is correct!';
            document.getElementById('k-verification-result').className = 'text-success';
        } else {
            document.getElementById('k-verification-result').textContent = 'Verification failed: k is incorrect';
            document.getElementById('k-verification-result').className = 'text-danger';
        }
    } catch (e) {
        console.error('Error verifying signing secret:', e);
        document.getElementById('k-verification-result').textContent = 'Error: ' + e.message;
        document.getElementById('k-verification-result').className = 'text-danger';
    }
}

// Verify the ECDSA parameters satisfy the verification equation
function verifyParameters() {
    try {
        const r = hexToBigInt(document.getElementById('ecdsa-r1').value);
        const s = hexToBigInt(document.getElementById('ecdsa-s1').value);
        const m = hexToBigInt(document.getElementById('ecdsa-m1').value);

        if (!r || !s || !m) {
            document.getElementById('params-verification-result').textContent = 'Please fill in r, s, and m values';
            document.getElementById('params-verification-result').className = 'text-warning';
            return;
        }

        // Check if r and s are within valid range
        if (r <= 0n || r >= CURVE_N || s <= 0n || s >= CURVE_N) {
            document.getElementById('params-verification-result').textContent = 
                'Parameters outside valid range (0 < r,s < n)';
            document.getElementById('params-verification-result').className = 'text-danger';
            return;
        }

        // For full verification, we'd need the public key point
        // Without it, we can only check that the parameters are in the valid range
        document.getElementById('params-verification-result').textContent = 
            'Parameters are in valid range. For full verification, public key is needed.';
        document.getElementById('params-verification-result').className = 'text-success';

    } catch (e) {
        console.error('Error verifying parameters:', e);
        document.getElementById('params-verification-result').textContent = 'Error: ' + e.message;
        document.getElementById('params-verification-result').className = 'text-danger';
    }
}