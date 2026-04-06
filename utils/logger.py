# utils/logger.py

COLORS = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "RED": "\033[31m",      # Critical/High
    "LIME": "\033[92m",     # Low/Info/Success
    "YELLOW": "\033[33m",   # Medium
    "CYAN": "\033[36m",     # Headers
    "GREY": "\033[90m"      # Metadata
}

def print_banner(target: str, mode: str, level: str) -> None:
    print(f"\n{COLORS['BOLD']}LISTENING ON MEOW{COLORS['RESET']}")
    print(f"  Target   : {target}")
    print(f"  Mode     : {mode.upper()}")
    print(f"  Severity : {level.upper()}\n")

def print_phase(title: str, cached: bool = False) -> None:
    cache_tag = f" {COLORS['GREY']}[Cached]{COLORS['RESET']}" if cached else ""
    print(f"\n{COLORS['CYAN']}[+]{COLORS['RESET']} {COLORS['BOLD']}{title}{COLORS['RESET']}{cache_tag}")

def print_warning_phase(title: str) -> None:
    print(f"\n{COLORS['YELLOW']}[*]{COLORS['RESET']} {COLORS['BOLD']}{title}{COLORS['RESET']}")

def print_active_phase(title: str) -> None:
    print(f"\n{COLORS['RED']}[>]{COLORS['RESET']} {COLORS['BOLD']}{title}{COLORS['RESET']}")

def print_item(text: str) -> None:
    print(f"    - {text}")

def print_sub_item(text: str) -> None:
    print(f"      └ {text}")

def print_sub_item_lime(text: str) -> None:
    print(f"      └ {COLORS['LIME']}{text}{COLORS['RESET']}")

def print_error(msg: str) -> None:
    print(f"\n{COLORS['RED']}[!] ERROR: {msg}{COLORS['RESET']}")

def print_vuln(severity: str, name: str, target: str, is_new: bool = True) -> None:
    sev_upper = severity.upper()
    if sev_upper in ["CRITICAL", "HIGH"]: color = COLORS["RED"]
    elif sev_upper == "MEDIUM": color = COLORS["YELLOW"]
    else: color = COLORS["LIME"]
        
    label = "BARU" if is_new else "LAMA"
    print(f"    {COLORS['BOLD']}[{color}{sev_upper}{COLORS['RESET']}{COLORS['BOLD']}] [{label}]{COLORS['RESET']} {name} : {target}")

def print_footer(new_vuln: int, old_vuln: int, report_path: str) -> None:
    print(f"\n{COLORS['LIME']}[+]{COLORS['RESET']} {COLORS['BOLD']}PEMINDAIAN SELESAI{COLORS['RESET']}")
    print(f"  Ancaman Baru : {COLORS['RED']}{new_vuln}{COLORS['RESET']}")
    print(f"  Ancaman Lama : {old_vuln}")
    print(f"  Intel Report : {COLORS['GREY']}{report_path}{COLORS['RESET']}\n")
