# 🛡️ Advanced Network Scanner

An advanced network scanning tool with CVE detection capabilities, designed for security professionals and network administrators.

## 🌟 Features

### 🔍 Multi-Protocol Discovery
- **WS-Discovery** (UDP 3702) - For IoT devices and printers
- **UPnP/SSDP** (UDP 1900) - For routers and media servers
- **mDNS** (UDP 5353) - For local network services
- **ARP Scanning** - For local network device discovery
- **ICMP Ping** - Basic connectivity testing

### 🔓 Comprehensive Port Scanning
- **TCP Port Scanning** - 26 common ports including:
  - 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP)
  - 53 (DNS), 80 (HTTP), 443 (HTTPS), 3306 (MySQL)
  - 3389 (RDP), 5432 (PostgreSQL), 8080 (HTTP Alternate)
- **UDP Port Scanning** - For DNS, SNMP, and other UDP services
- **Service Detection** - Identify services running on open ports

### 🛡️ CVE Detection
- **Database of 50+ CVEs** for common network services
- **Port-based vulnerability matching** - Automatically detect vulnerabilities based on open ports
- **Real-time vulnerability alerts** - Immediate notification of potential security issues
- **Severity classification** - Critical, High, Medium, Low vulnerability levels

### 📊 Advanced Reporting
- **Multiple Output Formats**:
  - JSON (default)
  - CSV (spreadsheet compatible)
  - XML (structured data)
  - HTML (web browser friendly)
- **Network Visualization**:
  - Text-based network maps
  - Simple topology views
  - Summary statistics
- **Comprehensive Logging** - Detailed scan logs for audit purposes

### ⚙️ Scanning Profiles
- **Default** - Standard network scan
- **Quick** - Fast scan of common ports
- **Comprehensive** - Thorough scan of all common ports
- **Stealth** - Slow, less aggressive scanning
- **IoT** - Optimized for IoT device detection
- **Server** - Optimized for server detection

### 🌐 Complex Network Support
- **Multiple Network Scanning** - Scan several networks in one operation
- **IP Exclusion Lists** - Skip specific IPs during scanning
- **VLAN Scanning** - Scan VLANs by ID or range
- **IPv6 Support** - Scan IPv6 networks
- **Network Validation** - Safety checks for all network operations

### 🎨 Enhanced UI/UX
- **Colorized Terminal Output** - Improved readability with colors
- **Animated Progress Indicators** - Visual feedback during operations
- **Formatted Menus** - Clear, intuitive interface
- **Interactive Prompts** - User-friendly input handling
- **ASCII Art Banner** - Professional appearance

### 🌐 Web Interface
- **Browser-Based GUI** - Alternative to CLI interface
- **Real-Time Status Updates** - Live progress monitoring
- **Scan Configuration** - Web forms for scan settings
- **Results Visualization** - Browser-friendly result display
- **API Endpoints** - RESTful API for integration

### 🛡️ Security Features
- **Safe Network Validation** - Only allows scanning of private networks
- **Port Validation** - Restricts scanning to known safe ports
- **Rate Limiting** - Prevents network flooding
- **Permission Checking** - Validates necessary system permissions
- **Result Obfuscation** - Privacy protection for sensitive data

## 🚀 Installation

```bash
# Clone the repository
git clone <repository-url>
cd upnp-scanner

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### CLI Interface
```bash
# Run the scanner
python main.py
```

### Web Interface
```bash
# Start the web interface
python web_interface.py

# Or start from the main menu (option 11)
python main.py
```

Open your browser to http://localhost:8080

### Menu Options:
1. **Scan Full Network** - Scan an entire network subnet
2. **Scan Single IP** - Scan a specific IP address
3. **Scan Specific Ports** - Scan custom port ranges
4. **Update CVE Database** - Update vulnerability database
5. **Update Scanner** - Update from GitHub
6. **Network Discovery** - Discover devices without port scanning
7. **Visualize Network** - Generate network maps and statistics
8. **Scan Multiple Networks** - Scan several networks at once
9. **Scan with IP Exclusions** - Skip specific IPs
10. **VLAN Scan** - Scan VLANs by ID or range
11. **Start Web Interface** - Launch browser-based GUI
12. **View Reports** - View previous scan results
13. **Exit** - Quit the application

## 📁 Project Structure

```
upnp-scanner/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── test_scanner.py        # Component testing script
├── update_scanner.py      # Automatic update script
├── termux_update.sh       # Termux-specific update script
├── web_interface.py       # Web-based GUI interface
│
├── config/                # Configuration files
│   ├── settings.py        # Global settings
│   └── profiles.py        # Scanning profiles
│
├── scanner/               # Core scanning modules
│   ├── core.py           # Main scanner class
│   ├── discovery.py      # Device discovery protocols
│   ├── port_scanner.py   # Port scanning functionality
│   ├── cve_checker.py    # CVE detection
│   ├── report.py         # Reporting functionality
│   └── vlan_scanner.py   # VLAN scanning utilities
│
├── utils/                 # Utility modules
│   ├── helpers.py        # General helper functions
│   ├── security.py       # Security validation
│   ├── cve_updater.py    # CVE database updates
│   ├── github_webhook.py # GitHub integration
│   ├── network_visualizer.py # Network visualization
│   └── cli_ui.py         # Enhanced CLI interface
│
└── data/                  # Data files
    └── cve_db.json       # CVE database
```

## 🔧 Configuration

### Scanning Profiles
The scanner supports different scanning profiles for various use cases:

- **Default**: Balanced scan for general use
- **Quick**: Fast scan focusing on common services
- **Comprehensive**: Thorough scan of all common ports
- **Stealth**: Slow scanning to avoid detection
- **IoT**: Optimized for Internet of Things devices
- **Server**: Focused on server detection

### Customization
Edit `config/settings.py` to modify:
- Scan timeouts
- Thread limits
- Port lists
- File paths

## 🌐 Complex Network Features

### Multiple Network Scanning
Scan multiple network subnets in a single operation:

```python
scanner.scan_multiple_networks(["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"])
```

### IP Exclusion Lists
Skip specific IPs during scanning to avoid critical systems:

```python
scanner.scan_with_exclusions("192.168.1.0/24", ["192.168.1.1", "192.168.1.254"])
```

### VLAN Scanning
Scan VLANs by ID or range:

```python
vlan_scanner = VLANScanner(scanner)
vlan_scanner.scan_vlan_range("192.168.0.0/24", 100, 110)
```

### IPv6 Support
Full support for IPv6 network scanning with safety validation.

## 🎨 UI/UX Improvements

### Colorized Output
Enhanced terminal interface with color-coded messages for better readability.

### Animated Progress
Visual feedback during long-running operations with animated progress indicators.

### Interactive Menus
User-friendly menus with clear options and intuitive navigation.

## 🌐 Web Interface

The scanner includes a built-in web interface for easier use, especially in environments like Termux where a GUI is beneficial.

### Features
- **Dashboard**: Overview of system status and recent results
- **Scan Configuration**: Web forms for setting up scans
- **Live Progress**: Real-time status updates during scans
- **Results Display**: Browser-friendly presentation of findings
- **RESTful API**: Programmatic access to scanner functionality

### Usage
1. Start the web interface: `python web_interface.py`
2. Open your browser to http://localhost:8080
3. Use the web interface to configure and run scans

### API Endpoints
- `GET /api/status` - Get current scan status
- `GET /api/results` - Get scan results
- `POST /api/scan_network` - Start a network scan

## 🛡️ Safety Features

The scanner includes multiple safety mechanisms:
- Only allows scanning of private networks (RFC 1918)
- Validates all ports against a safe list
- Implements rate limiting to prevent network flooding
- Checks system permissions before scanning
- Sanitizes all file paths to prevent directory traversal

## 📈 Output Formats

### JSON
Default structured output for programmatic use.

### CSV
Spreadsheet-compatible format for data analysis.

### XML
Structured format for integration with other tools.

### HTML
Browser-friendly reports with styling.

## 🌐 Network Visualization

### Text Maps
Simple text-based representation of discovered devices and vulnerabilities.

### Topology Views
ASCII-based network topology diagrams.

### Statistics
Summary reports showing:
- Total devices scanned
- Vulnerabilities found
- Service distribution
- Critical vulnerability count

## 📱 Termux Support

The scanner is fully compatible with Termux on Android devices.

### Termux Installation
```bash
# Install Termux from F-Droid (recommended)
# Install required packages
pkg update && pkg upgrade
pkg install python git

# Clone and install
git clone <repository-url>
cd upnp-scanner
pip install -r requirements.txt
```

### Termux Update
For easier updates in Termux, use the dedicated update script:
```bash
# Make the script executable
chmod +x termux_update.sh

# Run the update script
./termux_update.sh
```

Or use the built-in update feature from the main menu (option 5).

## 🔒 Security Considerations

This tool is designed for authorized security testing only. Always ensure you have permission before scanning any network.

### Safe Defaults
- Only scans private IP ranges (10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x)
- Limits scanning to known safe ports
- Implements rate limiting to prevent network disruption

### Privacy Features
- Result obfuscation for sensitive environments
- Secure file handling
- No external data transmission

## 🆘 Troubleshooting

### Common Issues
1. **Permission Errors**: Run with appropriate privileges for raw socket access
2. **Network Unreachable**: Ensure the target network is accessible
3. **Slow Scans**: Reduce thread count in settings for slower systems
4. **GitHub Update Failures in Termux**: Use the termux_update.sh script or ensure git is properly installed

### Termux-Specific Issues
- **Git not found**: Run `pkg install git`
- **Permission denied**: Ensure Termux has storage permissions
- **Network timeouts**: Check internet connection and try again

### Web Interface Issues
- **Port already in use**: Change the port in web_interface.py
- **Flask not found**: Install with `pip install flask`
- **Browser not opening**: Manually navigate to http://localhost:8080

### Support
For issues, please check the GitHub repository or contact the maintainers.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this tool
- CVE data sourced from public vulnerability databases
- Inspired by various network security tools and frameworks