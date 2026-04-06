# main.py
import argparse
import sys
import os
from core.scanner import MeowScanner
from utils.logger import print_error

def main() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

    parser = argparse.ArgumentParser(description="LISTENING ON MEOW - VULNERABILITY SCANNER")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", type=str, help="Target domain luas (Mode Subdomain Enumeration)")
    target_group.add_argument("-u", "--url", type=str, help="Target tunggal/spesifik (Mode Single Target)")
    
    parser.add_argument("-l", "--level", type=str, default="critical,high", help="Tingkat keparahan (critical, high, medium, low, info, all)")
    parser.add_argument("-m", "--mode", type=str, choices=["fast", "slow"], default="fast", help="Kecepatan scan")
    
    # [FITUR BARU] Flag kontrol Nuclei
    parser.add_argument("-n", "--nuclei", type=str, choices=["sniper", "full"], default="sniper", help="Mode Nuclei (sniper = fokus login/vuln, full = semua template)")
    
    parser.add_argument("-d", "--debug", action="store_true", help="Mode Debug")
    
    args = parser.parse_args()

    actual_target = args.url if args.url else args.target
    is_single_target = bool(args.url)

    # Memasukkan argumen nuclei ke dalam scanner
    scanner = MeowScanner(
        target=actual_target, 
        level=args.level, 
        mode=args.mode, 
        debug=args.debug, 
        single_target=is_single_target,
        nuclei_mode=args.nuclei # Flag baru diteruskan ke otak scanner
    )
    
    try:
        scanner.start_scan()
    except KeyboardInterrupt:
        print()
        print_error("Interupsi manual (Ctrl+C). Menghentikan sistem...")
        sys.exit(0)
    except Exception as e:
        print_error(f"Kegagalan fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
