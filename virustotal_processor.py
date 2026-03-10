
import os, json, hashlib, vt
from datetime import datetime
from dotenv import load_dotenv
from telegram_notifier import notify_vt_threat

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

class VirusTotalProcessor:
    def __init__(self, send_notifications=True):
        self.all_results = []
        self.send_notifications = send_notifications
    
    def save_results(self):
        if not self.all_results: 
            print("Нет данных для сохранения")
            return None
        
        # Создаем папку reports
        reports_dir = os.path.join(SCRIPT_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Сохраняем JSON
        f = f"vt_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        p = os.path.join(reports_dir, f)
        
        with open(p, 'w', encoding='utf-8') as f:
            json.dump({"results": self.all_results}, f, indent=2, default=str)
        print(f"JSON сохранен: {p}")
        
        # НЕ создаем график здесь - только возвращаем путь
        return p
    
    def check(self, url, name, type_name, client):
        obj = client.get_object(url)
        stats = dict(obj.last_analysis_stats)
        rep = getattr(obj, 'reputation', 0)
        print(f"\n{type_name}: {name}\n  Mal: {stats['malicious']} Susp: {stats['suspicious']} Rep: {rep}")
        r = {"timestamp": datetime.now().isoformat(), "type": type_name, "query": name, 
             "data": {"reputation": rep, "stats": stats}}
        self.all_results.append(r)
        if self.send_notifications:
            from telegram_notifier import notify_vt_threat
            notify_vt_threat(r, {"reputation": rep}, stats)
    
    def check_ip(self, ip):
        with vt.Client(API_KEY) as c:
            self.check(f"/ip_addresses/{ip}", ip, "ip", c)
    
    def check_domain(self, domain):
        with vt.Client(API_KEY) as c:
            self.check(f"/domains/{domain}", domain, "domain", c)
    
    def check_file(self, path):
        if not os.path.exists(path): 
            print("Файл не найден")
            return
        with open(path, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        with vt.Client(API_KEY) as c:
            try:
                o = c.get_object(f"/files/{h}")
                s = dict(o.last_analysis_stats)
                print(f"\nФайл: {path}\n  Mal: {s['malicious']}")
                r = {"timestamp": datetime.now().isoformat(), "type": "file", 
                     "query": path, "data": {"hash": h, "stats": s}}
                self.all_results.append(r)
                if self.send_notifications:
                    from telegram_notifier import notify_vt_threat
                    notify_vt_threat(r, {}, s)
            except:
                print("Файл не найден в VT")
    
    def interactive_mode(self):
        while True:
            print(f"\n[{len(self.all_results)}] 1.IP | 2.Домен | 3.Файл |"
                  f" 4.Сохранить и выйти | 5.Выход без сохранения")
            c = input("> ").strip()
            if c == "1": 
                self.check_ip(input("IP: "))
            elif c == "2": 
                self.check_domain(input("Домен: "))
            elif c == "3": 
                self.check_file(input("Путь: ").strip('"'))
            elif c == "4":
                self.save_results()  # Только сохраняем JSON
                break
            elif c == "5": 
                break