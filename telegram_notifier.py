import requests
import os
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_telegram_message(message, parse_mode="HTML"):
    """Отправляет сообщение в Telegram"""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram не настроен. Пропускаем...")
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": parse_mode
    }
    
    try:
        response = requests.post(url, data=data, timeout=5)
        if response.status_code == 200:
            return True
        else:
            print(f"Ошибка Telegram: {response.text}")
            return False
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")
        return False

def notify_suricata_alert(alert):
    """Уведомление об алерте Suricata"""
    severity = alert.get('severity', 3)
    if severity == 1:
        icon = "КРИТИЧЕСКАЯ"
    elif severity == 2:
        icon = "ВЫСОКАЯ"
    elif severity == 3:
        icon = "СРЕДНЯЯ"
    else:
        icon = "НИЗКАЯ"
    
    message = f"""
{icon} УГРОЗА SURICATA

Время: {alert.get('timestamp')}
Источник: {alert.get('src_ip')}:{alert.get('src_port')}
Цель: {alert.get('dest_ip')}:{alert.get('dest_port')}
Категория: {alert.get('category')}
Сигнатура: {alert.get('signature')}
Уровень: {severity}
    """
    return send_telegram_message(message)

def notify_vt_threat(result, attrs, stats):
    """Уведомление об угрозе из VirusTotal"""
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    reputation = attrs.get('reputation', 0)
    
    if malicious > 0:
        threat_level = "КРИТИЧЕСКАЯ УГРОЗА VT"
    elif suspicious > 0:
        threat_level = "ПОДОЗРИТЕЛЬНО VT"
    elif reputation < 0:
        threat_level = "НИЗКАЯ РЕПУТАЦИЯ VT"
    elif reputation < 10 and reputation > 0:
        threat_level = "РЕПУТАЦИЯ НИЖЕ СРЕДНЕГО VT"
    else:
        return False
    
    name = result['query']
    msg = f"""
{threat_level}

{result['type'].upper()}: {name[:50]}{'...' if len(name) > 50 else ''}

Статистика:
  Malicious: {malicious}
  Suspicious: {suspicious}
  Репутация: {reputation}
"""
    
    if 'country' in attrs:
        msg += f"   Страна: {attrs['country']}\n"
    if 'as_owner' in attrs:
        msg += f"   Владелец: {attrs['as_owner']}\n"
    
    return send_telegram_message(msg)

def notify_start(module):
    """Уведомление о запуске модуля"""
    send_telegram_message(f"Модуль {module} запущен")

def notify_end(module, results_count):
    """Уведомление о завершении модуля"""
    send_telegram_message(f"Модуль {module} завершен. Обработано: {results_count}")