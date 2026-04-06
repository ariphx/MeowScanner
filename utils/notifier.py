# utils/notifier.py
import logging
import requests
from config import ENABLE_TELEGRAM, TELE_TOKEN, TELE_CHAT_ID

logger = logging.getLogger("MeowNotifier")

def send_telegram_alert(target_url: str, vuln_name: str, severity: str) -> None:
    if not ENABLE_TELEGRAM:
        return

    message = (
        f"<b>VULNERABILITY DETECTED</b>\n\n"
        f"<b>Target:</b> {target_url}\n"
        f"<b>Issue:</b> {vuln_name}\n"
        f"<b>Severity:</b> {severity}"
    )
    url = f"https://api.telegram.org/bot{TELE_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TELE_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
    except Exception as e:
        logger.error(f"Gagal mengirim notifikasi Telegram: {e}")
