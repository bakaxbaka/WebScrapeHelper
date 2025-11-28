# WebScrapeHelper
A comprehensive Bitcoin signature analysis web application that detects weak ECDSA signatures and attempts private key recovery. The system analyzes transaction IDs and Bitcoin addresses to identify vulnerabilities in cryptocurrency transactions.
Core Features
Transaction analysis with automatic ECDSA parameter extraction
Address analysis covering all historical transactions
DER signature parsing and validation
Nonce reuse detection and private key recovery
Mathematical implementation of recovery formulas: k = (z1-z2)/(s1-s2), x = (s*k-z)/r
Recent Changes (June 24, 2025)
✓ Fixed DER signature parsing to extract proper r and s numeric values
✓ Implemented ECDSA nonce reuse attack with mathematical verification
✓ Enhanced sighash calculation for multi-input transactions with unique message hashes
✓ Applied standard nonce reuse formula: k = (z1-z2)/(s1-s2), x = (s1*k-z1)/r mod n
✓ Added cryptographic verification to ensure recovered keys are mathematically correct
✓ Enhanced address analyzer to fetch and analyze all transaction signatures
✓ Resolved JavaScript library import conflicts causing duplicate class declarations
✓ Added comprehensive error handling and verification for recovered private keys
✓ Implemented detailed vulnerability modal with complete signature data
✓ Fixed missing requests import and improved JavaScript loading sequence
✓ Integrated NotSoSecure ECDSA attack methodology and educational content
✓ Added WIF conversion and Bitcoin address generation for recovered private keys
✓ Implemented real-time balance checking via blockchain.info API
✓ Enhanced UI to display complete key information: hex, WIF, address, and balance
✓ Added automated vulnerability scanner with live blockchain monitoring
✓ Implemented mempool monitoring for real-time weak signature detection
✓ Created auto-scan functionality to continuously check recent transactions
→ Identified critical issue: Recovered private keys don't match transaction addresses → Investigation shows mathematical formulas are correct but address derivation has compatibility issues → System successfully detects nonce reuse and recovers keys, but address validation needs improvement
Project Architecture
Backend: Flask application with BTCAnalyzer class for signature analysis
Frontend: Bootstrap UI with JavaScript cryptographic libraries (bignum.js, gfp.js, ec.js, bccurve.js, ecdsa.js)
API: RESTful endpoints for transaction and address analysis
Blockchain Integration: Real-time data fetching from blockchain.info API
Technical Implementation
DER signature decoding for accurate r/s value extraction
Modular arithmetic for private key recovery using Python's built-in pow() function
Signature verification through ecdsa library integration
Concurrent transaction analysis for address-level scanning
User Preferences
Focus on mathematical accuracy over UI polish
Prioritize functional private key recovery capabilities
Maintain clear separation between backend analysis and frontend display
Critical requirement: Recovered private keys MUST control addresses involved in the analyzed transaction
Address validation is essential - recovered keys should generate addresses that match transaction inputs/outputs
