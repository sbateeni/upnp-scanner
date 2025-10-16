import json
import os
from datetime import datetime
from threading import Lock

# --- تأكد من أن هذا الملف موجود ---
CVE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cve_db.json")

def load_cve_database():
    """Load the CVE database from the JSON file."""
    try:
        with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: CVE database file not found at {CVE_DB_PATH}")
        return {"ports": {}}
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON in {CVE_DB_PATH}")
        return {"ports": {}}

def test_port_based_cve(exploited_devices: list, lock: Lock, ip: str, open_ports: list):
    """Test open ports against the loaded CVE database."""
    cve_db = load_cve_database()
    for port in open_ports:
        if str(port) in cve_db.get("ports", {}):
            service_info = cve_db["ports"][str(port)]
            service_name = service_info["service"]
            for cve in service_info["cves"]:
                print(
                    f"⚠️  POTENTIAL VULNERABILITY ON {ip}:{port} | "
                    f"Service: {service_name} | CVE: {cve['id']} | {cve['description']}"
                )
                exploited_entry = {
                    "ip": ip,
                    "port": port,
                    "service": service_name,
                    "cve_id": cve["id"],
                    "description": cve["description"],
                    "type": "port-based",
                    "timestamp": datetime.now().isoformat()
                }
                with lock:
                    exploited_devices.append(exploited_entry)