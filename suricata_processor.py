
import os
import json
import pandas as pd
from datetime import datetime
from telegram_notifier import notify_suricata_alert

def process_suricata_logs(file_path, send_notifications=True):
    """Обрабатывает логи Suricata"""
    print("\n" + "="*60)
    print("SURICATA LOG PROCESSOR")
    print("="*60)
    
    if not os.path.exists(file_path):
        print(f"Файл не найден: {file_path}")
        return None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    alerts = []
    for event in data:
        if event.get('event_type') == 'alert':
            alert = {
                'flow_id': event.get('flow_id'),
                'src_ip': event.get('src_ip'),
                'src_port': event.get('src_port'),
                'dest_ip': event.get('dest_ip'),
                'dest_port': event.get('dest_port'),
                'timestamp': event.get('timestamp'),
                'category': event.get('alert', {}).get('category'),
                'signature': event.get('alert', {}).get('signature'),
                'severity': event.get('alert', {}).get('severity'),
                'proto': event.get('proto')
            }
            alerts.append(alert)
            
            # Отправляем уведомления для критических
            if send_notifications and alert['severity'] == 1:
                notify_suricata_alert(alert)
    
    df = pd.DataFrame(alerts)
    print(f"Найдено алертов: {len(df)}")
    
    if len(df) > 0:
        # Сохраняем CSV
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_filename = os.path.join(reports_dir, f"suricata_alerts_{timestamp}.csv")
        df.to_csv(csv_filename, index=False, encoding='utf-8')
        print(f"CSV сохранен: {csv_filename}")
        
        # НЕ создаем график здесь!
        # Просто возвращаем DataFrame
        
        return df
    else:
        print("Нет алертов для обработки")
        return pd.DataFrame()  # Возвращаем пустой DataFrame