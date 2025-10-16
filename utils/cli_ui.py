"""Enhanced CLI UI components for better user experience."""

import sys
import time
from typing import List, Dict, Any

class EnhancedCLI:
    """Enhanced CLI interface with better user experience."""
    
    def __init__(self):
        self.colors = {
            'reset': '\033[0m',
            'bold': '\033[1m',
            'dim': '\033[2m',
            'red': '\033[31m',
            'green': '\033[32m',
            'yellow': '\033[33m',
            'blue': '\033[34m',
            'magenta': '\033[35m',
            'cyan': '\033[36m',
            'white': '\033[37m'
        }
        
    def supports_color(self) -> bool:
        """Check if the terminal supports color output."""
        try:
            # Check if we're in a terminal that supports colors
            if sys.platform == "win32":
                return True  # Windows 10+ supports ANSI colors
            return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        except:
            return False
            
    def colorize(self, text: str, color: str) -> str:
        """Apply color to text if terminal supports it."""
        if self.supports_color() and color in self.colors:
            return f"{self.colors[color]}{text}{self.colors['reset']}"
        return text
        
    def print_header(self, title: str):
        """Print a formatted header."""
        width = 60
        print("\n" + self.colorize("=" * width, 'cyan'))
        print(self.colorize(f"🛡️  {title}  🛡️", 'bold'))
        print(self.colorize("=" * width, 'cyan'))
        
    def print_menu_item(self, number: int, text: str, icon: str = ""):
        """Print a formatted menu item."""
        if icon:
            print(f"{self.colorize(str(number), 'yellow')}. {self.colorize(icon, 'green')} {text}")
        else:
            print(f"{self.colorize(str(number), 'yellow')}. {text}")
            
    def print_status(self, message: str, status: str = "info"):
        """Print a status message with appropriate coloring."""
        icons = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌",
            "critical": "🚨"
        }
        
        colors = {
            "info": "blue",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "critical": "red"
        }
        
        icon = icons.get(status, "ℹ️")
        color = colors.get(status, "blue")
        
        print(f"{self.colorize(icon, color)} {self.colorize(message, color)}")
        
    def print_progress(self, current: int, total: int, prefix: str = "Progress"):
        """Print a progress bar."""
        if total == 0:
            return
            
        percentage = int((current / total) * 100)
        bar_length = 30
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        print(f'\r{prefix} |{self.colorize(bar, "green")}| {percentage}% ({current}/{total})', end='\r')
        if current == total:
            print()  # New line when complete
            
    def print_device_list(self, devices: List[str]):
        """Print a formatted list of devices."""
        if not devices:
            self.print_status("No devices found.", "info")
            return
            
        print(f"\n{self.colorize('📱 Discovered Devices:', 'bold')}")
        print(self.colorize("-" * 30, 'dim'))
        
        for i, device in enumerate(devices, 1):
            print(f"  {self.colorize(str(i), 'yellow')}. {device}")
            
    def print_vulnerability(self, ip: str, port: int, service: str, cve_id: str, description: str):
        """Print a formatted vulnerability entry."""
        print(f"\n{self.colorize('⚠️  VULNERABILITY DETECTED', 'red')}")
        print(self.colorize("=" * 40, 'dim'))
        print(f"  {self.colorize('IP Address:', 'bold')} {ip}")
        print(f"  {self.colorize('Port:', 'bold')}      {port}")
        print(f"  {self.colorize('Service:', 'bold')}   {service}")
        print(f"  {self.colorize('CVE ID:', 'bold')}    {self.colorize(cve_id, 'red')}")
        print(f"  {self.colorize('Description:', 'bold')} {description}")
        
    def print_statistics(self, stats: Dict[str, Any]):
        """Print formatted scan statistics."""
        print(f"\n{self.colorize('📊 Scan Statistics:', 'bold')}")
        print(self.colorize("-" * 30, 'dim'))
        
        for key, value in stats.items():
            # Format the key to be more readable
            formatted_key = key.replace('_', ' ').title()
            print(f"  {self.colorize(formatted_key + ':', 'bold')} {value}")
            
    def print_network_info(self, network: str, device_count: int = 0):
        """Print formatted network information."""
        print(f"\n{self.colorize('📡 Network Information:', 'bold')}")
        print(self.colorize("-" * 30, 'dim'))
        print(f"  {self.colorize('Network:', 'bold')} {network}")
        if device_count > 0:
            print(f"  {self.colorize('Devices:', 'bold')}  {device_count}")
            
    def get_user_input(self, prompt: str, default: str = "") -> str:
        """Get user input with formatting."""
        if default:
            full_prompt = f"{self.colorize(prompt, 'cyan')} {self.colorize(f'[default: {default}]', 'dim')}: "
        else:
            full_prompt = f"{self.colorize(prompt, 'cyan')}: "
            
        try:
            user_input = input(full_prompt).strip()
            return user_input if user_input else default
        except KeyboardInterrupt:
            print(f"\n{self.colorize('Operation cancelled by user.', 'yellow')}")
            return ""
        except Exception as e:
            print(f"{self.colorize(f'Error reading input: {e}', 'red')}")
            return default
            
    def confirm_action(self, message: str) -> bool:
        """Get user confirmation for an action."""
        response = self.get_user_input(f"{message} (y/N)", "n")
        return response.lower() in ['y', 'yes']
        
    def print_table(self, headers: List[str], rows: List[List[str]]):
        """Print data in a formatted table."""
        if not rows:
            self.print_status("No data to display.", "info")
            return
            
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
                    
        # Print header
        header_row = " | ".join(header.ljust(col_widths[i]) for i, header in enumerate(headers))
        print(self.colorize("\n" + header_row, 'bold'))
        print(self.colorize("-" * len(header_row), 'dim'))
        
        # Print rows
        for row in rows:
            data_row = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
            print(data_row)
            
    def print_scan_summary(self, results: List[Dict[str, Any]]):
        """Print a comprehensive scan summary."""
        if not results:
            self.print_status("No vulnerabilities found.", "success")
            return
            
        # Group by severity
        critical = [r for r in results if any(keyword in r.get('description', '').lower() 
                                             for keyword in ['rce', 'critical', 'arbitrary code'])]
        high = [r for r in results if any(keyword in r.get('description', '').lower() 
                                         for keyword in ['dos', 'bypass', 'overflow']) 
               and r not in critical]
        medium = [r for r in results if r not in critical and r not in high]
        
        print(f"\n{self.colorize('🔍 Scan Summary:', 'bold')}")
        print(self.colorize("=" * 50, 'dim'))
        print(f"  {self.colorize('Total Vulnerabilities:', 'bold')} {len(results)}")
        print(f"  {self.colorize('Critical:', 'bold')} {self.colorize(str(len(critical)), 'red')}")
        print(f"  {self.colorize('High:', 'bold')}    {self.colorize(str(len(high)), 'yellow')}")
        print(f"  {self.colorize('Medium:', 'bold')}  {self.colorize(str(len(medium)), 'blue')}")
        
        if critical:
            print(f"\n{self.colorize('🚨 Critical Vulnerabilities:', 'red')}")
            for vuln in critical[:5]:  # Show first 5
                print(f"  • {vuln.get('ip', 'Unknown')}:{vuln.get('port', 'Unknown')} - {vuln.get('cve_id', 'Unknown')}")
                
    def animated_wait(self, message: str, duration: int = 3):
        """Show an animated waiting message."""
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for char in chars:
                sys.stdout.write(f'\r{self.colorize(message, "cyan")} {char}')
                sys.stdout.flush()
                time.sleep(0.1)
                
        sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')
        sys.stdout.flush()
        
    def clear_screen(self):
        """Clear the terminal screen."""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        """Print an ASCII art banner."""
        banner = f"""
{self.colorize('██████╗ ██╗   ██╗██████╗ ███████╗    ███╗   ██╗ █████╗ ███╗   ███╗███████╗██████╗ ', 'cyan')}
{self.colorize('██╔══██╗██║   ██║██╔══██╗██╔════╝    ████╗  ██║██╔══██╗████╗ ████║██╔════╝██╔══██╗', 'cyan')}
{self.colorize('██████╔╝██║   ██║██████╔╝█████╗      ██╔██╗ ██║███████║██╔████╔██║█████╗  ██████╔╝', 'cyan')}
{self.colorize('██╔═══╝ ██║   ██║██╔═══╝ ██╔══╝      ██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗', 'cyan')}
{self.colorize('██║     ╚██████╔╝██║     ███████╗    ██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║', 'cyan')}
{self.colorize('╚═╝      ╚═════╝ ╚═╝     ╚══════╝    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝', 'cyan')}
        """
        print(banner)
        print(self.colorize("Advanced Network Security Scanner".center(70), 'yellow'))
        print(self.colorize("🛡️  Professional | Secure | Comprehensive  🛡️".center(70), 'green'))
        print()