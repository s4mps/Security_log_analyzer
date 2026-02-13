#!/usr/bin/env python3
"""
Simplified Authentication Log Analyzer with Custom Data Structures and SQLite Persistence
"""

import re
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque
from custom_datastructures import CircularBuffer, AttackCounter

class AuthLogAnalyzer:
    def __init__(self, db_path="security_logs.db"):
        self.db_path = db_path
        self._init_database()
        self.reset()
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    source_user TEXT,
                    details TEXT NOT NULL,
                    attempt_count INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_timestamp TEXT NOT NULL,
                    attempt_timestamp DATETIME,
                    type TEXT NOT NULL,
                    severity TEXT,
                    user TEXT,
                    ip TEXT,
                    message TEXT,
                    is_critical BOOLEAN DEFAULT 0,
                    is_abnormal BOOLEAN DEFAULT 0,
                    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT,
                    total_lines INTEGER,
                    valid_entries INTEGER,
                    malformed_entries INTEGER,
                    warnings_generated INTEGER,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    duration_seconds REAL
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def reset(self):
        self.stats = defaultdict(int)
        self.log_entries = []
        self.warnings = []
        self.successful_logins = []
        self.failed_logins = []
        self._attempts_by_ip = AttackCounter()  # Using custom data structure
        self._attempts_by_user = AttackCounter()  # Using custom data structure
        self._critical_failures = []
        self.session_id = None
    
    def analyze_file(self, filepath):
        self.reset()
        self.session_id = self._start_analysis_session(filepath)
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    self._process_line(line.strip())
            
            # Run detection algorithms
            self._detect_brute_force()
            self._detect_suspicious_users()
            self._detect_abnormal_hours()
            self._detect_critical_failures()
            self._detect_suspicious_ips()
            self._detect_dictionary_attacks()
            self._detect_credential_stuffing()
            self._detect_port_scanning()
            
            # Populate backward-compatible lists
            self.successful_logins = [e for e in self.log_entries if e['type'] == 'success']
            self.failed_logins = [e for e in self.log_entries if e['type'] == 'failure']
            
            # Save warnings to database
            self._save_warnings_to_db()
            
            # Complete analysis session
            self._complete_analysis_session()
            
            return True
        except Exception as e:
            print(f"Error: {e}")
            self._record_error(str(e))
            return False
    
    def _start_analysis_session(self, filepath):
        """Start a new analysis session in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_sessions (file_path, start_time)
                VALUES (?, CURRENT_TIMESTAMP)
            ''', (filepath,))
            
            session_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return session_id
        except Exception as e:
            print(f"Error starting session: {e}")
            return None
    
    def _complete_analysis_session(self):
        """Complete the analysis session with statistics"""
        if not self.session_id:
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE analysis_sessions 
                SET total_lines = ?,
                    valid_entries = ?,
                    malformed_entries = ?,
                    warnings_generated = ?,
                    end_time = CURRENT_TIMESTAMP,
                    duration_seconds = (
                        strftime('%s', CURRENT_TIMESTAMP) - 
                        strftime('%s', start_time)
                    )
                WHERE id = ?
            ''', (
                self.stats['total_lines'],
                len(self.log_entries),
                self.stats.get('malformed_entries', 0),
                len(self.warnings),
                self.session_id
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error completing session: {e}")
    
    def _record_error(self, error_message):
        """Record error in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_sessions 
                (file_path, end_time, duration_seconds)
                VALUES (?, CURRENT_TIMESTAMP, 0)
            ''', (f"ERROR: {error_message}",))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error recording error: {e}")
    
    def _save_warnings_to_db(self):
        """Save all detected warnings to SQLite database"""
        if not self.warnings:
            return       
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()            
            for warning in self.warnings:
                cursor.execute('''
                    INSERT INTO security_warnings 
                    (timestamp, type, severity, source_ip, source_user, details, attempt_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    warning.get('timestamp', 'N/A'),
                    warning.get('type', 'unknown'),
                    warning.get('severity', 'INFO'),
                    warning.get('ip', None),
                    warning.get('user', None),
                    warning.get('details', 'No details'),
                    warning.get('attempt_count', 0)
                ))           
            # Also save login attempts for historical analysis
            for entry in self.log_entries:
                cursor.execute('''
                    INSERT INTO login_attempts 
                    (entry_timestamp, type, severity, user, ip, message, is_critical, is_abnormal)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.get('timestamp', 'N/A'),
                    entry.get('type', 'unknown'),
                    entry.get('severity', 'INFO'),
                    entry.get('user', None),
                    entry.get('ip', None),
                    entry.get('message', '')[:500],  # Limit message length
                    1 if entry.get('is_critical', False) else 0,
                    1 if entry.get('is_abnormal', False) else 0
                ))            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving to database: {e}")
    
    def _process_line(self, line):
        if not line:
            return
        
        self.stats['total_lines'] += 1
        parsed = self._parse_line(line)
        
        if not parsed:
            self._handle_malformed(line)
            return
        
        self.log_entries.append(parsed)
        self._track_for_detection(parsed)
    
    def _parse_line(self, line):
        patterns = [
            r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+):? (.+)$',
            r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (.+)$'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                timestamp, severity, message = match.groups()
                
                try:
                    datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return None
                
                if 'Successful login' in message:
                    return self._parse_successful(timestamp, severity, message)
                elif self._is_failed_login(message):
                    return self._parse_failed(timestamp, severity, message)
                else:
                    return {'type': 'other', 'timestamp': timestamp, 
                            'severity': severity, 'message': message}
        return None
    
    def _parse_successful(self, timestamp, severity, message):
        user = 'unknown'
        ip = 'unknown'
        
        user_match = re.search(r'for (\w+)', message)
        if user_match:
            user = user_match.group(1)
        
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            ip = ip_match.group(1)
        
        dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        is_abnormal = 1 <= dt.hour <= 5
        
        return {
            'type': 'success',
            'timestamp': timestamp,
            'severity': severity,
            'message': message,
            'user': user,
            'ip': ip,
            'is_abnormal': is_abnormal
        }
    
    def _parse_failed(self, timestamp, severity, message):
        user = 'unknown'
        ip = 'unknown'
        
        user_match = re.search(r'(?:for|user|Account) (\w+)', message)
        if user_match:
            user = user_match.group(1)
        
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            ip = ip_match.group(1)
        
        is_critical = any(keyword in message for keyword in 
                         ['Account locked', 'Password expired', 'Maximum authentication'])
        
        entry = {
            'type': 'failure',
            'timestamp': timestamp,
            'severity': severity,
            'message': message,
            'user': user,
            'ip': ip,
            'is_critical': is_critical
        }
        
        if is_critical:
            self._critical_failures.append(entry)
        
        return entry
    
    def _is_failed_login(self, message):
        keywords = ['Failed password', 'authentication failure', 'Invalid password', 
                   'Login failed', 'Account locked', 'Password expired',
                   'Connection closed', 'Invalid user', 'Did not receive identification']
        return any(keyword in message for keyword in keywords)
    
    def _handle_malformed(self, line):
        self.stats['malformed_entries'] += 1
        self.log_entries.append({
            'type': 'malformed',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'severity': 'UNKNOWN',
            'message': line
        })
    
    def _track_for_detection(self, parsed):
        timestamp = parsed.get('timestamp')
        if not timestamp:
            return
        
        try:
            dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return
        
        if parsed['type'] == 'failure':
            ip = parsed.get('ip')
            user = parsed.get('user')
            if ip and ip != 'unknown':
                self._attempts_by_ip.add_attempt(ip, dt)  # Using custom data structure
            if user and user != 'unknown':
                self._attempts_by_user.add_attempt(user, dt)  # Using custom data structure
    
    def _detect_brute_force(self):
        """Detect brute force: 3+ attempts within 30 seconds using custom data structure"""
        for ip in self._attempts_by_ip.get_all_keys():
            if ip == 'unknown':
                continue
            
            if self._attempts_by_ip.has_brute_force(ip, min_attempts=3, window_seconds=30):
                recent_attempts = self._attempts_by_ip.get_recent_attempts(ip, 30)
                self.warnings.append({
                    'type': 'brute_force_attack',
                    'severity': 'CRITICAL',
                    'details': f"Brute force: {len(recent_attempts)} attempts from {ip} in 30s",
                    'timestamp': recent_attempts[-1].strftime('%Y-%m-%d %H:%M:%S') if recent_attempts else 'N/A',
                    'ip': ip,
                    'attempt_count': len(recent_attempts)
                })
                self.stats['brute_force_detections'] += 1
    
    def _detect_suspicious_users(self):
        """Detect multiple failed attempts per user using custom data structure"""
        for user in self._attempts_by_user.get_all_keys():
            if user == 'unknown':
                continue
            
            if self._attempts_by_user.has_brute_force(user, min_attempts=3, window_seconds=600):
                recent_attempts = self._attempts_by_user.get_recent_attempts(user, 600)
                self.warnings.append({
                    'type': 'multiple_failed_attempts',
                    'severity': 'WARNING',
                    'details': f"Multiple failures: {len(recent_attempts)} attempts for {user} in 10min",
                    'timestamp': recent_attempts[-1].strftime('%Y-%m-%d %H:%M:%S') if recent_attempts else 'N/A',
                    'user': user,
                    'attempt_count': len(recent_attempts)
                })
    
    def _detect_abnormal_hours(self):
        """Detect abnormal hour logins"""
        for entry in self.log_entries:
            if entry['type'] == 'success' and entry.get('is_abnormal', False):
                self.warnings.append({
                    'type': 'abnormal_hours_login',
                    'severity': 'WARNING',
                    'details': f"Login during abnormal hours (1-5 AM): {entry.get('user')}",
                    'timestamp': entry['timestamp'],
                    'user': entry.get('user'),
                    'ip': entry.get('ip')
                })
    
    def _detect_critical_failures(self):
        """Detect critical failures"""
        for failure in self._critical_failures:
            self.warnings.append({
                'type': 'critical_failure',
                'severity': 'CRITICAL',
                'details': f"Critical: {failure['message'][:100]}",
                'timestamp': failure['timestamp'],
                'user': failure.get('user'),
                'ip': failure.get('ip')
            })
    
    def _detect_suspicious_ips(self):
        """Detect suspicious IPs (not brute force)"""
        for ip in self._attempts_by_ip.get_all_keys():
            if ip == 'unknown':
                continue
            
            # Check if already flagged as brute force
            has_brute_force = any(w['type'] == 'brute_force_attack' and w['ip'] == ip 
                                for w in self.warnings)
            
            # Get total attempts from custom data structure
            attempts = self._attempts_by_ip.get_recent_attempts(ip, window_seconds=86400)  # 24 hours
            if not has_brute_force and len(attempts) >= 3:
                self.warnings.append({
                    'type': 'suspicious_ip',
                    'severity': 'WARNING',
                    'details': f"Suspicious IP: {len(attempts)} total attempts from {ip}",
                    'timestamp': attempts[-1].strftime('%Y-%m-%d %H:%M:%S') if attempts else 'N/A',
                    'ip': ip,
                    'attempt_count': len(attempts)
                })
    
    def _detect_dictionary_attacks(self):
        """Detect dictionary attacks: many users from same IP"""
        ip_users = defaultdict(set)
        
        for entry in self.log_entries:
            if entry['type'] == 'failure':
                ip = entry.get('ip')
                user = entry.get('user')
                if ip != 'unknown' and user != 'unknown':
                    ip_users[ip].add(user)
        
        for ip, users in ip_users.items():
            if len(users) >= 4:
                self.warnings.append({
                    'type': 'dictionary_attack',
                    'severity': 'WARNING',
                    'details': f"Dictionary attack: {len(users)} users from {ip}",
                    'timestamp': self._get_last_timestamp_for_ip(ip),
                    'ip': ip,
                    'attempt_count': len(users)
                })
    
    def _detect_credential_stuffing(self):
        """Detect credential stuffing: same user from many IPs"""
        user_ips = defaultdict(set)
        
        for entry in self.log_entries:
            if entry['type'] == 'failure':
                ip = entry.get('ip')
                user = entry.get('user')
                if ip != 'unknown' and user != 'unknown':
                    user_ips[user].add(ip)
        
        for user, ips in user_ips.items():
            if len(ips) >= 3:
                self.warnings.append({
                    'type': 'credential_stuffing',
                    'severity': 'WARNING',
                    'details': f"Credential stuffing: {user} from {len(ips)} IPs",
                    'timestamp': self._get_last_timestamp_for_user(user),
                    'user': user,
                    'attempt_count': len(ips)
                })
    
    def _detect_port_scanning(self):
        """Detect port scanning"""
        scan_counts = defaultdict(int)
        
        for entry in self.log_entries:
            message = entry.get('message', '')
            if any(keyword in message for keyword in 
                  ['Connection closed', 'Invalid user', 'Did not receive identification']):
                ip = entry.get('ip')
                if ip != 'unknown':
                    scan_counts[ip] += 1
        
        for ip, count in scan_counts.items():
            if count >= 3:
                self.warnings.append({
                    'type': 'port_scanning',
                    'severity': 'WARNING',
                    'details': f"Port scanning: {count} attempts from {ip}",
                    'timestamp': self._get_last_timestamp_for_ip(ip),
                    'ip': ip,
                    'attempt_count': count
                })
    
    def _find_windows(self, attempts, window_seconds=30, min_attempts=3):
        """Find sliding windows with enough attempts"""
        if len(attempts) < min_attempts:
            return []
        
        attempts.sort(key=lambda x: x[0])
        windows = []
        window = deque()
        
        for dt, timestamp in attempts:
            window.append((dt, timestamp))
            
            while window and (dt - window[0][0]).total_seconds() > window_seconds:
                window.popleft()
            
            if len(window) >= min_attempts:
                windows.append((window[0][0], window[-1][0], list(window)))
        
        return windows
    
    def _get_last_timestamp_for_ip(self, ip):
        for entry in reversed(self.log_entries):
            if entry['type'] == 'failure' and entry.get('ip') == ip:
                return entry.get('timestamp', 'N/A')
        return 'N/A'
    
    def _get_last_timestamp_for_user(self, user):
        for entry in reversed(self.log_entries):
            if entry['type'] == 'failure' and entry.get('user') == user:
                return entry.get('timestamp', 'N/A')
        return 'N/A'
    
    def get_summary(self):
        successful = sum(1 for e in self.log_entries if e['type'] == 'success')
        failed = sum(1 for e in self.log_entries if e['type'] == 'failure')
        abnormal = sum(1 for e in self.log_entries if e['type'] == 'success' 
                      and e.get('is_abnormal', False))        
        # Get stats about custom data structure usage
        custom_ip_count = len(self._attempts_by_ip.get_all_keys())
        custom_user_count = len(self._attempts_by_user.get_all_keys())        
        # Get database stats
        db_stats = self._get_database_stats()
        
        return {
            'processing': {
                'total_lines': self.stats['total_lines'],
                'malformed_entries': self.stats.get('malformed_entries', 0),
                'valid_entries': len(self.log_entries),
                'custom_ds_ips_tracked': custom_ip_count,
                'custom_ds_users_tracked': custom_user_count
            },
            'login_analysis': {
                'successful_logins': successful,
                'failed_logins': failed,
                'abnormal_hour_logins': abnormal
            },
            'security_warnings': {
                'total_warnings': len(self.warnings),
                'brute_force_detections': sum(1 for w in self.warnings 
                                            if w['type'] == 'brute_force_attack')
            },
            'database_info': db_stats
        }
    
    def _get_database_stats(self):
        """Get statistics from the SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count warnings
            cursor.execute('SELECT COUNT(*) FROM security_warnings')
            total_warnings = cursor.fetchone()[0]
            
            # Count login attempts
            cursor.execute('SELECT COUNT(*) FROM login_attempts')
            total_logins = cursor.fetchone()[0]
            
            # Count analysis sessions
            cursor.execute('SELECT COUNT(*) FROM analysis_sessions')
            total_sessions = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_warnings_stored': total_warnings,
                'total_logins_stored': total_logins,
                'total_sessions': total_sessions,
                'database_file': self.db_path
            }
        except Exception as e:
            return {
                'database_error': str(e),
                'database_file': self.db_path
            }
    
    def get_warnings(self):
        return sorted(self.warnings, 
                     key=lambda x: datetime.strptime(x.get('timestamp', '1970-01-01 00:00:00'), 
                                                    '%Y-%m-%d %H:%M:%S'),
                     reverse=True)
    
    def get_entries_by_type(self, entry_type):
        return [e for e in self.log_entries if e['type'] == entry_type]
    
    def export_database_report(self, output_file=None):
        """Export database contents to a text report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"db_report_{timestamp}.txt"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_lines = [
                "="*60,
                "SECURITY LOG ANALYZER - DATABASE REPORT",
                "="*60,
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Database: {self.db_path}",
                ""
            ]
            
            # Get summary statistics
            cursor.execute('SELECT COUNT(*) FROM security_warnings')
            warning_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM login_attempts')
            login_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM analysis_sessions')
            session_count = cursor.fetchone()[0]
            
            report_lines.extend([
                "DATABASE STATISTICS:",
                f"  Total Security Warnings: {warning_count}",
                f"  Total Login Attempts: {login_count}",
                f"  Total Analysis Sessions: {session_count}",
                ""
            ])
            
            # Get recent warnings
            cursor.execute('''
                SELECT timestamp, type, severity, source_ip, details 
                FROM security_warnings 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''')
            recent_warnings = cursor.fetchall()
            
            if recent_warnings:
                report_lines.append("RECENT SECURITY WARNINGS (Last 10):")
                for warning in recent_warnings:
                    report_lines.append(f"  [{warning[0]}] {warning[1]} ({warning[2]})")
                    report_lines.append(f"     IP: {warning[3] or 'N/A'}")
                    report_lines.append(f"     Details: {warning[4][:100]}...")
                    report_lines.append("")
            
            # Get analysis sessions
            cursor.execute('''
                SELECT file_path, total_lines, warnings_generated, duration_seconds
                FROM analysis_sessions 
                ORDER BY start_time DESC 
                LIMIT 5
            ''')
            sessions = cursor.fetchall()
            
            if sessions:
                report_lines.append("RECENT ANALYSIS SESSIONS (Last 5):")
                for session in sessions:
                    report_lines.append(f"  File: {session[0] or 'N/A'}")
                    report_lines.append(f"     Lines: {session[1] or 'N/A'}")
                    report_lines.append(f"     Warnings: {session[2] or 'N/A'}")
                    report_lines.append(f"     Duration: {session[3] or 'N/A'} seconds")
                    report_lines.append("")
            
            conn.close()
            
            # Write report
            with open(output_file, 'w') as f:
                f.write('\n'.join(report_lines))
            
            return output_file
            
        except Exception as e:
            print(f"Error exporting database report: {e}")
            return None


# Quick test function
def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auth_analyzer.py <log_file>")
        print("       python auth_analyzer.py --db-report [output_file]")
        return
    
    analyzer = AuthLogAnalyzer()
    
    if sys.argv[1] == '--db-report':
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        report_file = analyzer.export_database_report(output_file)
        if report_file:
            print(f"Database report exported to: {report_file}")
        return
    
    if analyzer.analyze_file(sys.argv[1]):
        summary = analyzer.get_summary()
        print(f"Total entries: {summary['processing']['total_lines']}")
        print(f"Custom DS tracking: {summary['processing']['custom_ds_ips_tracked']} IPs, "
              f"{summary['processing']['custom_ds_users_tracked']} users")
        print(f"Warnings: {summary['security_warnings']['total_warnings']}")
        
        # Show database info
        if 'database_info' in summary:
            db_info = summary['database_info']
            print(f"\nDatabase Statistics:")
            print(f"  Total warnings stored: {db_info.get('total_warnings_stored', 'N/A')}")
            print(f"  Database file: {db_info.get('database_file', 'N/A')}")
        
        for warning in analyzer.get_warnings():
            print(f"[{warning['severity']}] {warning['type']}: {warning['details']}")

if __name__ == "__main__":
    main()