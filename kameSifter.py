#!/usr/bin/env python3
"""
kameSifter - Credential Validation Aggregator for Penetration Testing
Author: CyberKareem, github.com/cyberkareem
License: MIT
Description: Clean interface for testing credentials against SMB, LDAP, WMI, RDP, SSH, and more
WARNING: For authorized penetration testing only. Unauthorized access is illegal.
"""

import subprocess
import argparse
import sys
import os
from pathlib import Path
from typing import List, Tuple, Optional
import json
import re

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Service configurations
SERVICES = {
    'smb': {
        'tool': 'netexec',
        'protocol': 'smb',
        'description': 'SMB/CIFS (445)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'ldap': {
        'tool': 'netexec',
        'protocol': 'ldap',
        'description': 'LDAP (389/636)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'winrm': {
        'tool': 'netexec',
        'protocol': 'winrm',
        'description': 'WinRM (5985/5986)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'rdp': {
        'tool': 'netexec',
        'protocol': 'rdp',
        'description': 'RDP (3389)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'ssh': {
        'tool': 'netexec',
        'protocol': 'ssh',
        'description': 'SSH (22)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'mssql': {
        'tool': 'netexec',
        'protocol': 'mssql',
        'description': 'MSSQL (1433)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'wmi': {
        'tool': 'netexec',
        'protocol': 'wmi',
        'description': 'WMI',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    },
    'ftp': {
        'tool': 'netexec',
        'protocol': 'ftp',
        'description': 'FTP (21)',
        'success_indicators': ['Pwn3d!', '(Pwn3d!)']
    }
}

class ServicePwn:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.results = []
        
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if required tool is installed"""
        try:
            subprocess.run([tool_name, '--version'], 
                         capture_output=True, 
                         check=False,
                         timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def build_command(self, service: str, target: str, username: Optional[str] = None,
                     password: Optional[str] = None, user_file: Optional[str] = None,
                     password_file: Optional[str] = None, hash_value: Optional[str] = None,
                     hash_file: Optional[str] = None, domain: Optional[str] = None) -> List[str]:
        """Build the command for the specific service"""
        config = SERVICES[service]
        cmd = [config['tool'], config['protocol'], target]
        
        # Add domain if provided
        if domain:
            cmd.extend(['-d', domain])
        
        # Handle different credential scenarios
        if hash_value:
            # Single hash
            cmd.extend(['-H', hash_value])
            if username:
                cmd.extend(['-u', username])
        elif hash_file:
            # Hash file
            cmd.extend(['-H', hash_file])
            if user_file:
                cmd.extend(['-u', user_file])
            elif username:
                cmd.extend(['-u', username])
        elif user_file and password_file:
            # User file + password file
            cmd.extend(['-u', user_file, '-p', password_file])
        elif user_file and password:
            # User file + single password
            cmd.extend(['-u', user_file, '-p', password])
        elif username and password_file:
            # Single user + password file
            cmd.extend(['-u', username, '-p', password_file])
        elif username and password:
            # Single user + single password
            cmd.extend(['-u', username, '-p', password])
        else:
            # Try to enumerate without credentials
            cmd.append('--no-auth')
        
        return cmd
    
    def parse_output(self, output: str, service: str, target: str) -> dict:
        """Parse netexec/crackmapexec output"""
        lines = output.strip().split('\n')
        
        result = {
            'service': service,
            'target': target,
            'status': 'unknown',
            'pwned': False,
            'credentials': [],
            'open': False,
            'details': []
        }
        
        success_indicators = SERVICES[service]['success_indicators']
        
        for line in lines:
            # Check if service is open
            if service.upper() in line and target in line:
                result['open'] = True
            
            # Check for successful authentication
            if any(indicator in line for indicator in success_indicators):
                result['pwned'] = True
                result['status'] = 'pwned'
                
                # Try to extract credentials from the line
                cred_match = re.search(r'([^\s]+)\\([^\s]+):([^\s]+)', line)
                if cred_match:
                    domain, user, secret = cred_match.groups()
                    result['credentials'].append({
                        'domain': domain,
                        'username': user,
                        'secret': secret
                    })
            
            # Check for valid but not pwned
            elif '[+]' in line and target in line:
                if result['status'] == 'unknown':
                    result['status'] = 'valid_creds'
                result['open'] = True
                result['details'].append(line.strip())
            
            # Check for failures
            elif '[-]' in line and target in line:
                if result['status'] == 'unknown':
                    result['status'] = 'failed'
                result['details'].append(line.strip())
        
        return result
    
    def run_test(self, service: str, target: str, **kwargs) -> dict:
        """Run authentication test against a service"""
        
        # Build command
        cmd = self.build_command(service, target, **kwargs)
        
        if self.verbose:
            print(f"{Colors.CYAN}[*] Running: {' '.join(cmd)}{Colors.RESET}")
        
        try:
            # Run the command
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = process.stdout + process.stderr
            
            if self.verbose:
                print(f"{Colors.BLUE}[DEBUG] Raw output:\n{output}{Colors.RESET}")
            
            # Parse results
            result = self.parse_output(output, service, target)
            self.results.append(result)
            
            return result
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[!] Command timed out for {service}{Colors.RESET}")
            return {
                'service': service,
                'target': target,
                'status': 'timeout',
                'pwned': False,
                'open': False
            }
        except Exception as e:
            print(f"{Colors.RED}[!] Error running {service}: {str(e)}{Colors.RESET}")
            return {
                'service': service,
                'target': target,
                'status': 'error',
                'pwned': False,
                'open': False,
                'error': str(e)
            }
    
    def print_summary(self):
        """Print clean summary of results"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}SERVICEPWN RESULTS SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        pwned_count = 0
        open_count = 0
        
        for result in self.results:
            service_name = result['service'].upper()
            target = result['target']
            status = result['status']
            
            # Status symbol
            if result['pwned']:
                symbol = f"{Colors.GREEN}[PWNED]{Colors.RESET}"
                pwned_count += 1
            elif result['open']:
                symbol = f"{Colors.YELLOW}[OPEN]{Colors.RESET}"
                open_count += 1
            else:
                symbol = f"{Colors.RED}[CLOSED/FAILED]{Colors.RESET}"
            
            print(f"{symbol} {Colors.BOLD}{service_name:10}{Colors.RESET} | {target}")
            
            # Show credentials if pwned
            if result['credentials']:
                for cred in result['credentials']:
                    print(f"  {Colors.GREEN}└─ {cred['domain']}\\{cred['username']}:{cred['secret']}{Colors.RESET}")
            
            # Show additional details in verbose mode
            if self.verbose and result.get('details'):
                for detail in result['details'][:3]:  # Limit to 3 lines
                    print(f"  {Colors.BLUE}   {detail}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}Pwned Services: {pwned_count}{Colors.RESET}")
        print(f"{Colors.YELLOW}Open Services: {open_count}{Colors.RESET}")
        print(f"{Colors.RED}Failed/Closed: {len(self.results) - pwned_count - open_count}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    def export_json(self, filename: str):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"{Colors.GREEN}[+] Results exported to {filename}{Colors.RESET}")


def validate_file(filepath: str) -> str:
    """Validate that a file exists"""
    if not os.path.isfile(filepath):
        raise argparse.ArgumentTypeError(f"File not found: {filepath}")
    return filepath


def main():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║              ServicePwn v1.0                              ║
║      Credential Validation Aggregator                     ║
║      For Authorized Penetration Testing Only              ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    
    parser = argparse.ArgumentParser(
        description='Clean credential testing across multiple services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single credential against SMB
  servicepwn.py -t 192.168.1.10 -s smb -u admin -p Password123
  
  # Test user list against password list on multiple services
  servicepwn.py -t 192.168.1.10 -s smb,rdp,winrm -U users.txt -P passwords.txt
  
  # Test hash against target
  servicepwn.py -t 192.168.1.10 -s smb -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
  
  # Test all common services
  servicepwn.py -t 192.168.1.10 --all -u admin -p Password123
  
  # Export results to JSON
  servicepwn.py -t 192.168.1.10 -s smb -u admin -p Password123 -o results.json
        """
    )
    
    # Target
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or hostname')
    
    # Service selection
    service_group = parser.add_mutually_exclusive_group(required=True)
    service_group.add_argument('-s', '--services', 
                              help=f'Comma-separated services to test: {", ".join(SERVICES.keys())}')
    service_group.add_argument('--all', action='store_true',
                              help='Test all available services')
    
    # Authentication - Username
    user_group = parser.add_mutually_exclusive_group()
    user_group.add_argument('-u', '--username',
                           help='Single username')
    user_group.add_argument('-U', '--user-file', type=validate_file,
                           help='File containing usernames')
    
    # Authentication - Password
    pass_group = parser.add_mutually_exclusive_group()
    pass_group.add_argument('-p', '--password',
                           help='Single password')
    pass_group.add_argument('-P', '--password-file', type=validate_file,
                           help='File containing passwords')
    
    # Authentication - Hash
    hash_group = parser.add_mutually_exclusive_group()
    hash_group.add_argument('-H', '--hash',
                           help='NTLM hash (e.g., LM:NT or just NT)')
    hash_group.add_argument('--hash-file', type=validate_file,
                           help='File containing NTLM hashes')
    
    # Domain
    parser.add_argument('-d', '--domain',
                       help='Domain name (optional)')
    
    # Output options
    parser.add_argument('-o', '--output',
                       help='Export results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (show command details)')
    
    args = parser.parse_args()
    
    print(banner)
    
    # Initialize ServicePwn
    spwn = ServicePwn(verbose=args.verbose)
    
    # Check if netexec is installed
    if not spwn.check_tool_installed('netexec'):
        print(f"{Colors.RED}[!] Error: netexec is not installed{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install with: pip install netexec{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Or: apt install netexec{Colors.RESET}")
        sys.exit(1)
    
    # Determine services to test
    if args.all:
        services_to_test = list(SERVICES.keys())
    else:
        services_to_test = [s.strip().lower() for s in args.services.split(',')]
        # Validate services
        invalid = [s for s in services_to_test if s not in SERVICES]
        if invalid:
            print(f"{Colors.RED}[!] Invalid service(s): {', '.join(invalid)}{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Available: {', '.join(SERVICES.keys())}{Colors.RESET}")
            sys.exit(1)
    
    # Prepare credential arguments
    cred_args = {
        'username': args.username,
        'password': args.password,
        'user_file': args.user_file,
        'password_file': args.password_file,
        'hash_value': args.hash,
        'hash_file': args.hash_file,
        'domain': args.domain
    }
    
    # Run tests
    print(f"{Colors.CYAN}[*] Target: {args.target}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Services: {', '.join(services_to_test)}{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Starting tests...{Colors.RESET}\n")
    
    for service in services_to_test:
        print(f"{Colors.YELLOW}[*] Testing {service.upper()}...{Colors.RESET}")
        result = spwn.run_test(service, args.target, **cred_args)
    
    # Print summary
    spwn.print_summary()
    
    # Export if requested
    if args.output:
        spwn.export_json(args.output)
    
    # Exit code based on results
    if any(r['pwned'] for r in spwn.results):
        sys.exit(0)  # Success - found valid creds
    else:
        sys.exit(1)  # No successful authentications


if __name__ == '__main__':
    main()
