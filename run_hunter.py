
#!/usr/bin/env python3
"""
Bitcoin ECDSA Vulnerability Hunter
Runs continuously until weak signatures are found
"""

import subprocess
import sys
import time

def run_continuous_scanner():
    """Run the continuous scanner"""
    try:
        print("🚀 Starting Continuous ECDSA Scanner...")
        subprocess.run([sys.executable, "continuous_scanner.py"])
    except KeyboardInterrupt:
        print("\n🛑 Scanner stopped by user")
    except Exception as e:
        print(f"❌ Scanner error: {e}")

def run_enhanced_hunter():
    """Run the enhanced async hunter"""
    try:
        print("🔥 Starting Enhanced Vulnerability Hunter...")
        subprocess.run([sys.executable, "enhanced_hunter.py"])
    except KeyboardInterrupt:
        print("\n🛑 Hunter stopped by user")
    except Exception as e:
        print(f"❌ Hunter error: {e}")

def main():
    print("""
🎯 Bitcoin ECDSA Weak Signature Hunter
=====================================

Choose your hunting mode:
1. Continuous Scanner (multi-threaded)
2. Enhanced Hunter (async, faster)
3. Run both simultaneously

Enter choice (1-3): """, end="")
    
    choice = input().strip()
    
    if choice == "1":
        run_continuous_scanner()
    elif choice == "2":
        run_enhanced_hunter()
    elif choice == "3":
        print("🚀 Starting both hunters...")
        import threading
        
        t1 = threading.Thread(target=run_continuous_scanner)
        t2 = threading.Thread(target=run_enhanced_hunter)
        
        t1.start()
        time.sleep(2)  # Stagger startup
        t2.start()
        
        try:
            t1.join()
            t2.join()
        except KeyboardInterrupt:
            print("\n🛑 All hunters stopped")
    else:
        print("❌ Invalid choice. Use 1, 2, or 3.")

if __name__ == "__main__":
    main()
