// Bitcoin address and transaction validation utilities

function validateTransactionId(txId) {
    // Bitcoin transaction IDs are 64-character hex strings
    const pattern = /^[a-fA-F0-9]{64}$/;
    return pattern.test(txId);
}

function validateBitcoinAddress(address) {
    // Basic validation for Bitcoin addresses
    // Supports legacy, SegWit and native SegWit addresses
    
    if (!address || typeof address !== 'string') {
        return false;
    }
    
    // Legacy address format (1...)
    if (/^1[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(address)) {
        return true;
    }
    
    // P2SH address format (3...)
    if (/^3[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(address)) {
        return true;
    }
    
    // Bech32 address format (bc1...)
    if (/^bc1[a-zA-HJ-NP-Z0-9]{25,89}$/.test(address)) {
        return true;
    }
    
    return false;
}

function validateSignatureComponents(r, s) {
    // Validate that r and s are valid hex strings
    const hexPattern = /^[a-fA-F0-9]+$/;
    
    if (!hexPattern.test(r) || !hexPattern.test(s)) {
        return false;
    }
    
    // Check lengths (should be 64 characters each for 256-bit numbers)
    if (r.length !== 64 || s.length !== 64) {
        return false;
    }
    
    return true;
}

function formatBitcoinAmount(satoshis) {
    return (satoshis / 100000000).toFixed(8);
}

function shortenAddress(address, length = 8) {
    if (!address) return '';
    return `${address.substring(0, length)}...${address.substring(address.length - length)}`;
}

function formatTimestamp(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}
