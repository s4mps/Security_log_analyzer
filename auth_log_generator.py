#!/usr/bin/env python3
"""
Enhanced Authentication Log Generator with Attack Patterns
"""

import os
import random
from datetime import datetime, timedelta

# Create directory
os.makedirs('auth_logs', exist_ok=True)

def generate_auth_log(filename, entries=100):
    """Generate authentication log file with attack patterns"""
    
    with open(filename, 'w') as f:
        # Start time
        timestamp = datetime.now() - timedelta(hours=24)
        
        # Normal users and suspicious IPs
        normal_users = ['john', 'sarah', 'mike', 'admin', 'user1', 'user2']
        normal_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
        suspicious_ips = ['45.123.45.67', '185.220.101.50', '103.45.67.89']
        
        # Track login attempts per IP for brute force simulation
        ip_attempts = {}
        severity = 'INFO'  # Initialize severity variable
        
        for entry_num in range(entries):
            # Increment time
            timestamp += timedelta(seconds=random.randint(1, 120))
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            # 70% successful logins, 30% failed
            if random.random() < 0.70:
                # Successful login
                user = random.choice(normal_users)
                ip = random.choice(normal_ips)
                
                # Check for abnormal login time (between 1 AM - 5 AM)
                hour = timestamp.hour
                if 1 <= hour <= 5:
                    severity = 'WARNING'
                    message = f'Successful login for {user} from {ip} (abnormal hours)'
                else:
                    severity = 'INFO'
                    message = f'Successful login for {user} from {ip}'
                
                log_line = f'{time_str} {severity} {message}\n'
            
            else:
                # Failed login
                user = random.choice(['root', 'admin', 'administrator', 'test'])
                ip = random.choice(suspicious_ips)
                
                # Track attempts for brute force
                if ip not in ip_attempts:
                    ip_attempts[ip] = 0
                ip_attempts[ip] += 1
                
                # Different types of failed login messages
                failed_messages = [
                    f'Failed password for {user} from {ip}',
                    f'authentication failure for {user} from {ip}',
                    f'Invalid password for {user} from {ip}',
                    f'Login failed for {user} from {ip}'
                ]
                
                severity = 'ERROR'
                message = random.choice(failed_messages)
                log_line = f'{time_str} {severity} {message}\n'
                
                # Add brute force pattern (multiple rapid failures)
                if ip_attempts.get(ip, 0) > 5 and random.random() < 0.7:
                    # Add extra failed attempts in rapid succession
                    for _ in range(random.randint(3, 8)):
                        timestamp += timedelta(seconds=random.uniform(0.1, 1.0))
                        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        message = random.choice(failed_messages)
                        f.write(f'{time_str} {severity} {message}\n')
                    ip_attempts[ip] = 0  # Reset after burst
            
            f.write(log_line)
            
            # ADDED: Occasionally insert attack patterns
            if random.random() < 0.05:  # 5% chance to insert an attack pattern
                attack_type = random.choice(['dictionary', 'credential_stuffing', 'port_scan'])
                
                if attack_type == 'dictionary':
                    # Dictionary attack: many users from same IP
                    dict_ip = f'198.51.100.{random.randint(1, 254)}'
                    dict_users = ['root', 'admin', 'administrator', 'test', 'guest', 
                                'user', 'ubuntu', 'oracle', 'mysql']
                    
                    for i in range(random.randint(5, 10)):
                        timestamp += timedelta(seconds=random.uniform(0.2, 1.0))
                        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        user = random.choice(dict_users)
                        f.write(f'{time_str} ERROR Failed password for {user} from {dict_ip}\n')
                
                elif attack_type == 'credential_stuffing':
                    # Credential stuffing: same user from many IPs
                    stuff_user = 'admin'
                    for i in range(random.randint(4, 8)):
                        timestamp += timedelta(seconds=random.uniform(0.5, 2.0))
                        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        ip = f'10.20.{random.randint(1, 3)}.{random.randint(1, 254)}'
                        f.write(f'{time_str} ERROR Invalid password for {stuff_user} from {ip}\n')
                
                elif attack_type == 'port_scan':
                    # Port scanning activity
                    scan_ip = f'203.0.113.{random.randint(1, 254)}'
                    for i in range(random.randint(3, 6)):
                        timestamp += timedelta(seconds=random.uniform(0.1, 0.5))
                        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        messages = [
                            f'Connection closed by {scan_ip} [preauth]',
                            f'Invalid user test from {scan_ip}',
                            f'Did not receive identification string from {scan_ip}'
                        ]
                        f.write(f'{time_str} WARNING {random.choice(messages)}\n')
        
        # Add some malformed lines (5%)
        for _ in range(entries // 20):
            timestamp += timedelta(seconds=random.randint(1, 30))
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            malformed_lines = [
                f'{time_str} CORRUPTED_LOG_ENTRY',
                f'INVALID_TIMESTAMP {severity} Random garbage data',
                f'{time_str} INFO',
                f'{time_str} {severity}'
            ]
            f.write(random.choice(malformed_lines) + '\n')

def main():
    """Main function"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    print("="*50)
    print("Authentication Log Generator with Attack Patterns")
    print("="*50)
    
    # Generate sample logs
    generate_auth_log(f'auth_logs/auth_{timestamp}.log', 150)
    generate_auth_log(f'auth_logs/auth_large_{timestamp}.log', 300)
    
    print("Generated log files:")
    print(f"  ✓ auth_logs/auth_{timestamp}.log")
    print(f"  ✓ auth_logs/auth_large_{timestamp}.log")
    print("\nLog types included:")
    print("  • Successful logins (normal hours)")
    print("  • Successful logins (abnormal hours - 1 AM to 5 AM)")
    print("  • Failed logins with different error messages")
    print("  • Brute force patterns (multiple rapid failures)")
    print("  • Dictionary attacks (many users from same IP)")
    print("  • Credential stuffing (same user from many IPs)")
    print("  • Port scanning activity")
    print("  • Malformed log entries (5%)")
    print("="*50)

if __name__ == "__main__":
    main()