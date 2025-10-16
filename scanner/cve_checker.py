import json
import os
from datetime import datetime
from threading import Lock
import re

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
    vulnerabilities_found = 0
    
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
                    vulnerabilities_found += 1
    
    return vulnerabilities_found

def search_cve_by_keyword(keyword: str) -> list:
    """Search for CVEs by keyword in the database."""
    cve_db = load_cve_database()
    matching_cves = []
    
    # Search in service names and CVE descriptions
    for port, service_info in cve_db.get("ports", {}).items():
        service_name = service_info["service"]
        if keyword.lower() in service_name.lower():
            matching_cves.extend(service_info["cves"])
        else:
            for cve in service_info["cves"]:
                if keyword.lower() in cve["description"].lower() or keyword.lower() in cve["id"].lower():
                    matching_cves.append(cve)
    
    return matching_cves

def get_cve_details(cve_id: str) -> dict:
    """Get detailed information about a specific CVE."""
    cve_db = load_cve_database()
    
    # Search for the CVE ID in the database
    for port, service_info in cve_db.get("ports", {}).items():
        for cve in service_info["cves"]:
            if cve["id"] == cve_id:
                return {
                    "cve_id": cve_id,
                    "port": port,
                    "service": service_info["service"],
                    "description": cve["description"]
                }
    
    return {"error": f"CVE {cve_id} not found in database"}

def update_cve_severity(cve_db: dict) -> dict:
    """Add severity levels to CVEs based on keywords in their descriptions."""
    severity_keywords = {
        "critical": ["rce", "remote code execution", "arbitrary code", "privilege escalation"],
        "high": ["dos", "denial of service", "bypass", "authentication bypass", "overflow"],
        "medium": ["xss", "cross-site scripting", "csrf", "cross-site request forgery"],
        "low": ["information disclosure", "info leak", "enumeration"]
    }
    
    for port, service_info in cve_db.get("ports", {}).items():
        for cve in service_info.get("cves", []):
            description = cve["description"].lower()
            severity = "unknown"
            
            for level, keywords in severity_keywords.items():
                if any(keyword in description for keyword in keywords):
                    severity = level
                    break
                    
            cve["severity"] = severity
    
    return cve_db