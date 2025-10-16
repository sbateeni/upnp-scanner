"""Configuration profiles for different scanning scenarios."""

# Default scanning profile
DEFAULT_PROFILE = {
    "name": "default",
    "description": "Standard network scan",
    "ports": [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 1521, 1883, 
              3306, 3389, 5000, 5432, 5900, 631, 8080, 8443, 9000, 9090, 9100],
    "timeout": 3.0,
    "max_threads": 100,
    "discovery_methods": ["wsd", "ssdp", "mdns"],
    "report_formats": ["json", "csv", "xml", "html"]
}

# Quick scan profile (fewer ports, faster)
QUICK_PROFILE = {
    "name": "quick",
    "description": "Quick scan of common ports",
    "ports": [22, 80, 443, 3306, 3389, 8080],
    "timeout": 2.0,
    "max_threads": 50,
    "discovery_methods": ["ssdp"],
    "report_formats": ["json", "csv"]
}

# Comprehensive scan profile (more ports, thorough)
COMPREHENSIVE_PROFILE = {
    "name": "comprehensive",
    "description": "Comprehensive scan of all common ports",
    "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 
              1521, 1883, 2049, 3306, 3389, 5000, 5432, 5900, 631, 8080, 8443, 8888, 
              9000, 9090, 9100, 9200, 11211, 27017],
    "timeout": 5.0,
    "max_threads": 200,
    "discovery_methods": ["wsd", "ssdp", "mdns", "icmp"],
    "report_formats": ["json", "csv", "xml", "html"]
}

# Stealth scan profile (slower, less aggressive)
STEALTH_PROFILE = {
    "name": "stealth",
    "description": "Stealth scan with randomized timing",
    "ports": [22, 80, 443, 3306, 3389],
    "timeout": 5.0,
    "max_threads": 10,
    "discovery_methods": ["ssdp"],
    "report_formats": ["json"]
}

# IoT devices scan profile
IOT_PROFILE = {
    "name": "iot",
    "description": "Scan optimized for IoT devices",
    "ports": [21, 22, 23, 53, 80, 5000, 8080, 8443, 9100, 161],
    "timeout": 4.0,
    "max_threads": 75,
    "discovery_methods": ["wsd", "ssdp", "mdns"],
    "report_formats": ["json", "csv"]
}

# Server scan profile
SERVER_PROFILE = {
    "name": "server",
    "description": "Scan optimized for server detection",
    "ports": [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 
              3389, 5432, 5900, 8080, 8443, 9000, 9090, 9200, 11211, 27017],
    "timeout": 3.0,
    "max_threads": 150,
    "discovery_methods": ["wsd", "ssdp"],
    "report_formats": ["json", "csv", "xml", "html"]
}

def get_profile(profile_name: str) -> dict:
    """Get a scanning profile by name."""
    profiles = {
        "default": DEFAULT_PROFILE,
        "quick": QUICK_PROFILE,
        "comprehensive": COMPREHENSIVE_PROFILE,
        "stealth": STEALTH_PROFILE,
        "iot": IOT_PROFILE,
        "server": SERVER_PROFILE
    }
    
    return profiles.get(profile_name.lower(), DEFAULT_PROFILE)

def list_profiles() -> list:
    """List all available scanning profiles."""
    return [
        DEFAULT_PROFILE,
        QUICK_PROFILE,
        COMPREHENSIVE_PROFILE,
        STEALTH_PROFILE,
        IOT_PROFILE,
        SERVER_PROFILE
    ]