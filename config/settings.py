import os
from datetime import datetime

# Network scanning settings
SCAN_TIMEOUT = 3.0  # seconds
MAX_THREADS = 100
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 1521, 1883, 
    3306, 3389, 5000, 5432, 5900, 631, 8080, 8443, 9000, 9090, 9100
]

# File paths
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = f"scan_report_{TIMESTAMP}.log"
RESULTS_FILE = f"exploited_devices_{TIMESTAMP}.json"

# HTTP settings
HTTP_TIMEOUT = 5.0
USER_AGENT = "NetworkScanner/1.0"