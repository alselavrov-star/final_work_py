
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime

def get_reports_dir():
    """Возвращает путь к папке reports"""
    # Получаем путь к директории, где находится этот файл
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(script_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def plot_vt_results(data, out=None):
    try:
        results = data.get('results', [])
        if not results: 
            return print("Нет данных")
        
        # Собираем данные
        names, mal, susp, reps, rnames = [], [], [], [], []
        for r in results:
            if not r.get('data'): continue
            d = r['data']
            name = r['query'][:15] + ('...' if len(r['query']) > 15 else '')
            names.append(name)
            mal.append(d.get('stats', {}).get('malicious', 0))
            susp.append(d.get('stats', {}).get('suspicious', 0))
            if 'reputation' in d:
                rnames.append(name)
                reps.append(d['reputation'])
        
        if not names: 
            return print("Нет данных для графика")
        
        # График
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Детекты
        x = np.arange(len(names))
        w = 0.35
        ax1.bar(x - w/2, mal, w, label='Malicious', color='#ff4444')
        ax1.bar(x + w/2, susp, w, label='Suspicious', color='#ff8800')
        ax1.set_title('Детекты по объектам')
        ax1.set_xticks(x)
        ax1.set_xticklabels(names, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(alpha=0.3)
        
        # Репутация
        if reps:
            colors = ['#00C851' if v>0 else "#ff2e2e" for v in reps]
            ax2.barh(rnames, reps, color=colors)
            ax2.set_title('Репутация')
            ax2.axvline(x=0, color='black', ls='--', alpha=0.5)
        
        plt.suptitle(f'VirusTotal: {len(results)} объектов')
        plt.tight_layout()
        
        # Сохраняем в папку reports
        reports_dir = get_reports_dir()
        if out is None:
            out = f"vt_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        # Если out содержит путь, используем его, иначе добавляем reports_dir
        if os.path.dirname(out):
            full_path = out
        else:
            full_path = os.path.join(reports_dir, out)
        
        plt.savefig(full_path, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"График VT сохранен: {full_path}")
        
    except Exception as e:
        print(f"Ошибка графика VT: {e}")

def plot_suricata_alerts(df, out=None):
    try:
        if df is None or df.empty:
            return print("Нет данных Suricata")
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        # Топ источников
        top_src = df['src_ip'].value_counts().head(8)
        ax1.barh(range(len(top_src)), top_src.values, color='#ff4444')
        ax1.set_yticks(range(len(top_src)))
        ax1.set_yticklabels([i[:15] for i in top_src.index])
        ax1.set_title('Топ источников угроз')
        ax1.set_xlabel('Количество')
        
        # Топ целей
        top_dst = df['dest_ip'].value_counts().head(8)
        ax2.barh(range(len(top_dst)), top_dst.values, color='#ff8800')
        ax2.set_yticks(range(len(top_dst)))
        ax2.set_yticklabels([i[:15] for i in top_dst.index])
        ax2.set_title('Топ целей атак')
        ax2.set_xlabel('Количество')
        
        # Severity
        sev = df['severity'].value_counts().sort_index()
        labs = {1:'Критический', 2:'Высокий', 3:'Средний', 4:'Низкий'}
        colors = ['#ff4444','#ff8800','#ffbb33','#00C851'][:len(sev)]
        ax3.pie(sev.values, labels=[labs.get(s,str(s)) for s in sev.index], 
                autopct='%1.0f%%', colors=colors)
        ax3.set_title('Уровень опасности')
        
        # Категории
        top_cat = df['category'].value_counts().head(8)
        bars = ax4.bar(range(len(top_cat)), top_cat.values, color=plt.cm.viridis(np.linspace(0, 1, 8)))
        ax4.set_xticks(range(len(top_cat)))
        ax4.set_xticklabels([c[:15] + ('...' if len(c) > 15 else '') for c in top_cat.index], rotation=45, ha='right')
        ax4.set_title('Топ категорий угроз')
        ax4.set_ylabel('Количество')
        
        # Добавляем значения на столбцы
        for i, (bar, val) in enumerate(zip(bars, top_cat.values)):
            ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                    str(val), ha='center', va='bottom', fontsize=9)
        
        plt.suptitle(f'Suricata Alerts: всего {len(df)}', fontsize=14)
        plt.tight_layout()
        
        # Сохраняем в папку reports
        reports_dir = get_reports_dir()
        if out is None:
            out = f"suricata_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        # Если out содержит путь, используем его, иначе добавляем reports_dir
        if os.path.dirname(out):
            full_path = out
        else:
            full_path = os.path.join(reports_dir, out)
        
        plt.savefig(full_path, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"График Suricata сохранен: {full_path}")
        
    except Exception as e:
        print(f"Ошибка графика Suricata: {e}")