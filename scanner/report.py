import json
import logging
import csv
from datetime import datetime
from config.settings import LOG_FILE
import xml.etree.ElementTree as ET

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

def save_results_csv(exploited_devices: list, csv_file: str):
    """Save the list of vulnerable devices to a CSV file."""
    if not exploited_devices:
        return
        
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow(['IP Address', 'Port', 'Service', 'CVE ID', 'Description', 'Timestamp'])
        
        # Write data
        for device in exploited_devices:
            writer.writerow([
                device.get('ip', ''),
                device.get('port', ''),
                device.get('service', ''),
                device.get('cve_id', ''),
                device.get('description', ''),
                device.get('timestamp', '')
            ])

def save_results_xml(exploited_devices: list, xml_file: str):
    """Save the list of vulnerable devices to an XML file."""
    if not exploited_devices:
        return
        
    root = ET.Element("vulnerability_scan")
    root.set("timestamp", datetime.now().isoformat())
    
    for device in exploited_devices:
        device_elem = ET.SubElement(root, "vulnerable_device")
        for key, value in device.items():
            child = ET.SubElement(device_elem, key)
            child.text = str(value)
    
    tree = ET.ElementTree(root)
    tree.write(xml_file, encoding='utf-8', xml_declaration=True)

def save_results_html(exploited_devices: list, html_file: str):
    """Save the list of vulnerable devices to an HTML file."""
    if not exploited_devices:
        return
        
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .info { color: blue; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Scan completed at: {}</p>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Port</th>
            <th>Service</th>
            <th>CVE ID</th>
            <th>Description</th>
            <th>Timestamp</th>
        </tr>
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    for device in exploited_devices:
        html_content += """
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td class="critical">{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>
""".format(
            device.get('ip', ''),
            device.get('port', ''),
            device.get('service', ''),
            device.get('cve_id', ''),
            device.get('description', ''),
            device.get('timestamp', '')
        )
    
    html_content += """
    </table>
</body>
</html>
"""
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

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