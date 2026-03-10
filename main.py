
import os
import threading
import time
import queue
from dotenv import load_dotenv
from suricata_processor import process_suricata_logs
from virustotal_processor import VirusTotalProcessor
import matplotlib
from pathlib import Path
matplotlib.use('Agg')

load_dotenv()

# Глобальные переменные
suricata_result = None
suricata_done = False
suricata_error = None
vt_results = None

def run_suricata_processing():
    """Запускает обработку Suricata"""
    global suricata_result, suricata_done, suricata_error
    print("\n Запуск обработки Suricata...")
    PROJECT_ROOT = Path(__file__).parent
    dotenv_path = PROJECT_ROOT / '.env'
    load_dotenv(dotenv_path)
    log_filename = os.getenv("SURICATA_LOG_PATH")
    
    if log_filename:
        log_path = PROJECT_ROOT / log_filename
        log_path = str(log_path)  # преобразуем обратно в строку если нужно
    else:
        log_path = None
    
    try:
        df = process_suricata_logs(log_path, send_notifications=True)
        if df is not None:
            suricata_result = df
            print(f"Suricata: обработано {len(df)} алертов")
    except Exception as e:
        suricata_error = str(e)
    finally:
        suricata_done = True
        print("🏁 Поток Suricata завершен")

def run_virustotal_interactive():
    """Запускает интерактивный режим VirusTotal"""
    global vt_results
    print("\n Запуск VirusTotal...")
    vt = VirusTotalProcessor(send_notifications=True)
    vt.interactive_mode()
    if vt.all_results:
        vt_results = vt.all_results
        print(f"VirusTotal: {len(vt_results)} проверок")

def generate_plots():
    """Генерирует графики - ТОЛЬКО ОДИН РАЗ"""
    from plot_generator import plot_suricata_alerts, plot_vt_results
    from datetime import datetime
    
    print("\n Генерация графиков...")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    plots_created = 0
    
    # График Suricata
    if suricata_result is not None and not suricata_result.empty:
        try:
            plot_suricata_alerts(suricata_result, f"suricata_plot_{timestamp}.png")
            plots_created += 1
        except Exception as e:
            print(f"Ошибка графика Suricata: {e}")
    else:
        print("Нет данных Suricata для графика")
    
    # График VirusTotal
    if vt_results:
        try:
            plot_vt_results({"results": vt_results}, f"vt_plot_{timestamp}.png")
            plots_created += 1
        except Exception as e:
            print(f"Ошибка графика VT: {e}")
    else:
        print("Нет данных VirusTotal для графика")
    
    print(f"Создано графиков: {plots_created}")

def parallel_processing():
    """Параллельная обработка"""
    global suricata_done, suricata_result, vt_results
    
    print("\n" + "="*60)
    print("ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА")
    print("="*60)
    
    # Сбрасываем глобальные переменные
    suricata_result = None
    suricata_done = False
    vt_results = None
    
    # Запускаем Suricata
    suricata_thread = threading.Thread(target=run_suricata_processing)
    suricata_thread.daemon = True
    suricata_thread.start()
    
    time.sleep(1)
    
    # Запускаем VirusTotal
    print("\n VirusTotal (интерактивный режим)")
    run_virustotal_interactive()
    
    # Ждем Suricata
    print("\n Ожидание завершения Suricata...")
    while not suricata_done:
        time.sleep(1)
        print(f"   Ожидание...", end='\r')
    
    print("\nSuricata завершена")
    
    # Генерируем графики ОДИН РАЗ
    generate_plots()
    
    print("\n Параллельная обработка завершена")

def main():
    print("="*60)
    print("SECURITY ANALYZER")
    print("="*60)
    print("1. Только Suricata")
    print("2. Только VirusTotal")
    print("3. Параллельно")
    print("4. Выход")
    print("="*60)
    
    choice = input("\n Выберите (1-4): ").strip()
    
    try:
        if choice == "1":
            run_suricata_processing()
            # Ждем завершения
            time.sleep(2)
            generate_plots()
        elif choice == "2":
            run_virustotal_interactive()
            generate_plots()
        elif choice == "3":
            parallel_processing()
        elif choice == "4":
            print("Выход")
    except KeyboardInterrupt:
        print("\n\n Прервано")

if __name__ == "__main__":
    main()
