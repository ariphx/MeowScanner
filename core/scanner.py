# core/scanner.py
import json
import subprocess
import os
import requests
from typing import Optional, List, Dict

from utils.db_manager import init_db, is_new_finding, save_finding
from utils.notifier import send_telegram_alert
import utils.logger as log
from core.analyzer import MeowAnalyzer

class MeowScanner:
    # [FITUR BARU] Menambahkan nuclei_mode di parameter
    def __init__(self, target: str, level: str = "critical,high", mode: str = "fast", debug: bool = False, single_target: bool = False, nuclei_mode: str = "sniper") -> None:
        self.target = target
        self.level = level.lower()
        self.mode = mode.lower()
        self.debug = debug
        self.single_target = single_target
        self.nuclei_mode = nuclei_mode.lower()
        init_db()

        if self.mode == "slow":
            self.rl_httpx, self.rl_katana, self.rl_nuclei = "-rl 10", "-rl 10", "-rl 10 -mhe 3"
            self.rl_ffuf = "-t 2 -p 1 -sa" 
        else:
            self.rl_httpx, self.rl_katana, self.rl_nuclei = "-rl 100", "-rl 150", "-rl 150 -mhe 10"
            self.rl_ffuf = "-t 30 -sa"

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _run_command(self, command: str) -> Optional[str]:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
            if result.returncode != 0 and not result.stdout.strip(): return None
            return result.stdout
        except Exception: return None

    def _check_waf_block(self) -> bool:
        log.print_phase("Pemeriksaan Status Jaringan (WAF/IPS)")
        url = self.target if self.target.startswith("http") else f"http://{self.target}"
        try:
            r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5, verify=False)
            if r.status_code in [403, 406, 429]:
                log.print_item(f"Terblokir WAF/IPS (HTTP {r.status_code})")
                return True
            log.print_item("Koneksi aman. Target dapat dijangkau.")
            return False
        except: return False

    def _is_completed(self, filepath: str) -> bool:
        return os.path.exists(filepath) and os.path.getsize(filepath) > 0

    def start_scan(self) -> None:
        log.print_banner(self.target, self.mode, self.level)
        
        safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        workspace_dir = os.path.join(os.getcwd(), "workspaces", safe_target)
        os.makedirs(workspace_dir, exist_ok=True)
        
        f_subs = os.path.join(workspace_dir, "subs.txt")
        f_ports = os.path.join(workspace_dir, "ports.txt")
        f_live = os.path.join(workspace_dir, "live.txt")
        f_fuzz = os.path.join(workspace_dir, "fuzz.txt")
        f_crawl = os.path.join(workspace_dir, "crawl.txt")
        final_target_file = os.path.join(workspace_dir, "final_target.txt")
        report_file = os.path.join(workspace_dir, "meow_report.txt")

        report_insights, report_actions = [], []

        try:
            clean_host = self.target.split("://")[1] if "://" in self.target else self.target
            clean_host = clean_host.split("/")[0].split(":")[0]
            is_direct = self.target.startswith("http") or "/" in self.target

            # 1. ENUMERASI
            log.print_phase("Enumerasi Aset Target", cached=self._is_completed(f_subs))
            if not self._is_completed(f_subs):
                if self.single_target or is_direct:
                    with open(f_subs, 'w') as f: f.write(f"{clean_host}\n")
                else:
                    self._run_command(f"subfinder -d {clean_host} -silent -o {f_subs}")
            
            with open(f_subs, 'r') as f:
                subs = [l.strip() for l in f if l.strip()]
                log.print_item(f"Ditemukan {len(subs)} catatan DNS (validasi keaktifan di fase profil).")

            # 2. PORT SCAN
            log.print_phase("Penemuan Port Jaringan", cached=self._is_completed(f_ports))
            if not self._is_completed(f_ports):
                self._run_command(f"naabu -l {f_subs} -silent -o {f_ports}")

            COMMON_PORTS = {
                '21':'FTP','22':'SSH','25':'SMTP','53':'DNS','80':'HTTP','110':'POP3','143':'IMAP',
                '443':'HTTPS','445':'SMB','465':'SMTP-SSL','587':'SMTP-TLS','993':'IMAP-SSL','995':'POP3-SSL',
                '1433':'MSSQL','3306':'MySQL','3389':'RDP','5432':'PostgreSQL','5060':'SIP/VoIP',
                '6379':'Redis','7070':'RealAudio','8080':'HTTP-Proxy','8008':'HTTP-Alt','2000':'Mikrotik'
            }

            port_map = {}
            with open(f_ports, 'r') as f:
                for line in f:
                    if ":" in line:
                        h, p = line.strip().rsplit(":", 1)
                        port_map.setdefault(h, []).append(f"{p} ({COMMON_PORTS.get(p, 'Unknown')})")
            
            for h, p_list in list(port_map.items()):
                log.print_item(f"{h} -> {', '.join(p_list)}")
                for p_info in p_list: report_actions.append(f"[PORT] Audit layanan pada {h}:{p_info}")

            # 3. LIVE HOSTS & TECH
            log.print_phase("Profil Teknologi & Layanan", cached=self._is_completed(f_live))
            if not self._is_completed(f_live):
                self._run_command(f"httpx -l {f_ports} {self.rl_httpx} -silent -o {f_live}")

            if self._is_completed(f_live):
                techs = self._run_command(f"httpx -l {f_live} -tech-detect -silent")
                if techs:
                    for t in list(dict.fromkeys(techs.strip().split('\n'))):
                        if " [" in t:
                            u, info = t.split(" [", 1)
                            log.print_item(u)
                            log.print_sub_item_lime(info.replace("]", ""))

            # 4. ATTACK SURFACE
            log.print_phase("Pemetaan Permukaan Serangan", cached=self._is_completed(f_fuzz))
            if not self._is_completed(f_fuzz):
                wl = os.path.expanduser("~/wordlists/dirs.txt")
                ff_json = os.path.join(workspace_dir, "ffuf_raw.json")
                self._run_command(f"ffuf -w {f_live}:URL -w {wl}:FUZZ -u URL/FUZZ -mc 200,301,302 -of json -o {ff_json} -silent")
                if os.path.exists(ff_json):
                    with open(ff_json, 'r') as jf, open(f_fuzz, 'w') as out:
                        data = json.load(jf)
                        for r in data.get("results", []): out.write(r["url"] + "\n")
            
            if not self._is_completed(f_crawl):
                self._run_command(f"katana -list {f_live} -jc -silent -o {f_crawl}")

            all_urls = set()
            for fp in [f_live, f_fuzz, f_crawl]:
                if self._is_completed(fp):
                    with open(fp, 'r') as f: all_urls.update([l.strip() for l in f if l.strip()])
            with open(final_target_file, 'w') as f: f.write("\n".join(list(all_urls)))

            # 5. SNIPER: ADMIN PANEL HUNTER
            admin_kws = ["admin", "login", "panel", "dashboard", "setup", "manage", "config", "wp-login"]
            admin_links = sorted(list(set([u for u in all_urls if any(k in u.lower() for k in admin_kws)])))

            if admin_links:
                log.print_warning_phase(f"Ditemukan {len(admin_links)} Panel Manajemen")
                for link in admin_links[:15]: log.print_sub_item(link)
                for link in admin_links: report_actions.append(f"[WEB] Audit Otentikasi: {link}")

            if self._check_waf_block(): return

            # 6. REPORT GENERATION
            with open(report_file, 'w') as f:
                f.write(f"MEOW THREAT REPORT: {self.target}\n" + "="*50 + "\n")
                for act in set(report_actions): f.write(f"- {act}\n")

            # 7. NUCLEI (DYNAMIC MODE CONTROL)
            log.print_active_phase(f"Eksekusi Penilaian Dinamis [{self.level.upper()}]\n")
            
            # [LOGIKA FLAG -n]
            if self.nuclei_mode == "sniper":
                log.print_item("Mode SNIPER: Fokus pada Vulnerabilities, Exposure, & Default Logins...")
                cmd = f"nuclei -l {final_target_file} {self.rl_nuclei} -silent -j -t default-logins -t vulnerabilities -t exposure"
            else:
                log.print_item("Mode FULL: Mengeksekusi SELURUH template Nuclei (Carpet Bombing)...")
                cmd = f"nuclei -l {final_target_file} {self.rl_nuclei} -silent -j"

            if self.level != "all": 
                cmd += f" -severity {self.level}"
            
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
            new_v, old_v, seen = 0, 0, set()
            for line in iter(proc.stdout.readline, ''):
                try:
                    res = json.loads(line.strip())
                    id = f"{res.get('matched-at')}|{res.get('info').get('name')}"
                    if id in seen: continue
                    seen.add(id)
                    sev, name, url = res.get("info").get("severity"), res.get("info").get("name"), res.get("matched-at")
                    if is_new_finding(id):
                        new_v += 1
                        log.print_vuln(sev, name, url, True)
                        save_finding(id, url, name, sev)
                        send_telegram_alert(url, name, sev)
                    else:
                        old_v += 1
                        log.print_vuln(sev, name, url, False)
                except: pass
            
            proc.wait()
            log.print_footer(new_v, old_v, report_file)

        finally: pass
