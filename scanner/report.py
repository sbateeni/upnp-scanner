import json
import logging
from datetime import datetime
from config.settings import LOG_FILE

def setup_logger():
    """Set up logger for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def save_results(exploited_devices: list, results_file: str):
    """Save the list of vulnerable devices to a JSON file."""
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(exploited_devices, f, indent=4, ensure_ascii=False)

def view_report():
    """View the last scan report."""
    import glob
    reports = glob.glob("scan_report_*.log")
    if not reports:
        print("❌ No scan reports found.")
        return
    print("\n📋 Available scan reports:")
    for i, report in enumerate(reports):
        print(f"  {i+1}. {report}")
    try:
        choice = int(input("Enter report number to view (or 0 to cancel): "))
        if choice == 0:
            return
        selected_report = reports[choice - 1]
        with open(selected_report, "r", encoding="utf-8") as f:
            print("\n" + "="*60)
            print(f"📄 Content of {selected_report}:")
            print("="*60)
            print(f.read())
    except (ValueError, IndexError):
        print("❌ Invalid selection.")