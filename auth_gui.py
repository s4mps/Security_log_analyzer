#!/usr/bin/env python3
"""
Simplified GUI for Authentication Log Analyzer
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from auth_analyzer import AuthLogAnalyzer
from datetime import datetime
import os

class AuthLogAnalyzerGUI:
    """Simplified GUI for Authentication Log Analyzer"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Security Log Analyzer")
        self.root.geometry("1200x750")
        
        self.analyzer = AuthLogAnalyzer()
        self.current_file = None
        
        # Colors (blue theme)
        self.colors = {
            'main_bg': '#e3f2fd',
            'header_bg': '#1976d2',
            'button_bg': '#2196f3',
            'panel_bg': '#ffffff',
            'text_bg': '#ffffff',
            'alert_red': '#f44336',
            'warning_orange': '#ff9800',
            'success_green': '#4caf50'
        }
        
        self.setup_gui()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Load a log file")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_gui(self):
        """Setup the GUI layout"""
        self.root.configure(bg=self.colors['main_bg'])
        
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['main_bg'], padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = tk.Label(main_frame, text="🔐 Security Log Analyzer", 
                         font=("Arial", 20, "bold"),
                         bg=self.colors['header_bg'], fg='white')
        header.pack(fill=tk.X, pady=(0, 15))
        
        # Control panel
        self.setup_control_panel(main_frame)
        
        # Content area
        content_frame = tk.Frame(main_frame, bg=self.colors['main_bg'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log content panel
        self.setup_log_panel(content_frame)
        
        # Analysis panel
        self.setup_analysis_panel(content_frame)
    
    def setup_control_panel(self, parent):
        """Setup control buttons and file label"""
        control_frame = tk.Frame(parent, bg=self.colors['main_bg'])
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.file_label = tk.Label(control_frame, text="📁 No file loaded", 
                                  font=("Arial", 11), bg=self.colors['main_bg'])
        self.file_label.pack(side=tk.LEFT)
        
        btn_frame = tk.Frame(control_frame, bg=self.colors['main_bg'])
        btn_frame.pack(side=tk.RIGHT)
        
        buttons = [
            ("📁 Load", self.load_log),
            ("🔍 Analyze", self.analyze_logs),
            ("📤 Export", self.export_report),
            ("🗑️ Clear", self.clear_data)
        ]
        
        for text, command in buttons:
            btn = tk.Button(btn_frame, text=text, command=command,
                           bg=self.colors['button_bg'], fg='white',
                           font=("Arial", 10), padx=15, pady=8)
            btn.pack(side=tk.LEFT, padx=3)
    
    def setup_log_panel(self, parent):
        """Setup log content panel"""
        log_frame = tk.LabelFrame(parent, text="📝 Log Content", 
                                 font=("Arial", 12, "bold"),
                                 bg=self.colors['panel_bg'])
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=25, wrap=tk.WORD,
                                                 font=("Consolas", 10),
                                                 bg=self.colors['text_bg'])
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.configure(state='disabled')
    
    def setup_analysis_panel(self, parent):
        """Setup analysis results panel"""
        right_panel = tk.Frame(parent, bg=self.colors['main_bg'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(right_panel, text="📊 Analysis Results", 
                font=("Arial", 14, "bold"),
                bg=self.colors['main_bg']).pack(anchor=tk.W, pady=(0, 10))
        
        # Notebook for tabs
        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_tabs(notebook)
        
        # Alert details
        self.setup_alert_details(right_panel)
    
    def create_tabs(self, notebook):
        """Create all analysis tabs"""
        # Tab configurations
        tab_configs = [
            ("🔴 Failed", ["Time", "User", "IP"], 
             ["Timestamp", "User", "IP Address"], [150, 100, 120],
             self.show_failed_details),
            
            ("✅ Success", ["Time", "User", "IP", "Status"],
             ["Timestamp", "User", "IP Address", "Status"],
             [150, 100, 120, 80], self.show_success_details),
            
            ("⚠️ Warnings", ["Type", "Severity", "Source", "Time"],
             ["Warning Type", "Severity", "Source", "Time"],
             [150, 100, 150, 150], self.show_warning_details)
        ]
        
        self.trees = {}
        
        for tab_text, columns, headings, widths, callback in tab_configs:
            frame = tk.Frame(notebook, bg=self.colors['panel_bg'])
            notebook.add(frame, text=tab_text)
            
            # Store treeview reference by tab name
            tab_name = tab_text.replace("🔴 ", "").replace("✅ ", "").replace("⚠️ ", "").lower()
            self.trees[tab_name] = self.create_treeview(frame, columns, headings, widths, callback)
        
        # Summary tab
        summary_frame = tk.Frame(notebook, bg=self.colors['panel_bg'])
        notebook.add(summary_frame, text="📋 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=20, wrap=tk.WORD,
                                                     font=("Arial", 10),
                                                     bg=self.colors['text_bg'])
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.summary_text.configure(state='disabled')
    
    def create_treeview(self, parent, columns, headings, widths, bind_callback=None):
        """Create a reusable treeview widget"""
        frame = tk.Frame(parent, bg=self.colors['panel_bg'])
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        
        # Configure headings and columns
        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading)
            tree.column(col, width=width)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind callback if provided
        if bind_callback:
            tree.bind("<<TreeviewSelect>>", bind_callback)
        
        return tree
    
    def setup_alert_details(self, parent):
        """Setup alert details panel"""
        alert_frame = tk.LabelFrame(parent, text="⚠️ Alert Details", 
                                   font=("Arial", 12, "bold"),
                                   bg=self.colors['panel_bg'])
        alert_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.alert_text = scrolledtext.ScrolledText(alert_frame, height=10, wrap=tk.WORD,
                                                   font=("Consolas", 10),
                                                   bg=self.colors['text_bg'])
        self.alert_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.alert_text.configure(state='disabled')
    
    def update_text_widget(self, widget, content, state='disabled'):
        """Helper to update text widgets"""
        widget.configure(state='normal')
        widget.delete(1.0, tk.END)
        widget.insert(1.0, content)
        widget.configure(state=state)
    
    def load_log(self):
        """Load log file"""
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            filename = os.path.basename(file_path)
            self.file_label.config(text=f"📁 Loaded: {filename}")
            self.current_file = file_path
            
            # Update log display with syntax highlighting
            self.update_log_display(content)
            self.status_var.set(f"Loaded {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def update_log_display(self, content):
        """Update log text with syntax highlighting"""
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        
        # Configure tags for syntax highlighting
        self.log_text.tag_configure('alert', foreground=self.colors['alert_red'])
        self.log_text.tag_configure('warning', foreground=self.colors['warning_orange'])
        self.log_text.tag_configure('success', foreground=self.colors['success_green'])
        
        # Add content with appropriate tags
        for line in content.strip().split('\n'):
            if not line.strip():
                continue
            
            tag = None
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in ['failed', 'failure', 'invalid', 'error', 'locked']):
                tag = 'alert'
            elif any(keyword in line_lower for keyword in ['warning', 'abnormal']):
                tag = 'warning'
            elif 'successful' in line_lower:
                tag = 'success'
            
            if tag:
                self.log_text.insert(tk.END, line + '\n', tag)
            else:
                self.log_text.insert(tk.END, line + '\n')
        
        self.log_text.configure(state='disabled')
    
    def analyze_logs(self):
        """Analyze loaded log"""
        if not self.current_file:
            messagebox.showwarning("No File", "Please load a log file first")
            return
        
        self.status_var.set("Analyzing...")
        self.root.update()
        
        try:
            # Reset analyzer
            self.analyzer = AuthLogAnalyzer()  # Recreate analyzer to clear old data
            
            # Analyze file
            if self.analyzer.analyze_file(self.current_file):
                # Update displays
                self.update_all_displays()
                
                # Show appropriate message based on results
                summary = self.analyzer.get_summary()
                self.status_var.set("Analysis complete")
                
                if summary['security_warnings']['total_warnings'] > 0:
                    messagebox.showwarning("Security Alert", 
                                         f"Found {summary['security_warnings']['total_warnings']} security warnings!")
                else:
                    messagebox.showinfo("Analysis Complete", 
                                      f"Found {summary['login_analysis']['failed_logins']} failed logins")
            else:
                messagebox.showerror("Analysis Error", "Failed to analyze the log file")
                self.status_var.set("Analysis failed")
                
        except Exception as e:
            messagebox.showerror("Error", f"Analysis error: {str(e)}")
            self.status_var.set("Error during analysis")
    
    def update_all_displays(self):
        """Update all GUI displays"""
        self.update_failed_logins()
        self.update_successful_logins()
        self.update_warnings()
        self.update_summary()
        self.update_alert_details()
    
    def update_failed_logins(self):
        """Update failed logins table"""
        tree = self.trees['failed']
        tree.delete(*tree.get_children())
        
        # Use the backward-compatible list from analyzer
        failed_logins = getattr(self.analyzer, 'failed_logins', [])
        if not failed_logins:
            failed_logins = self.analyzer.get_entries_by_type('failure')
        
        for login in failed_logins[:30]:
            tree.insert("", tk.END, values=(
                login.get('timestamp', 'N/A'),
                login.get('user', 'unknown'),
                login.get('ip', 'unknown')
            ))
    
    def update_successful_logins(self):
        """Update successful logins table"""
        tree = self.trees['success']
        tree.delete(*tree.get_children())
        
        # Use the backward-compatible list from analyzer
        successful_logins = getattr(self.analyzer, 'successful_logins', [])
        if not successful_logins:
            successful_logins = self.analyzer.get_entries_by_type('success')
        
        for login in successful_logins[:30]:
            status = "Abnormal" if login.get('is_abnormal', False) else "Normal"
            tree.insert("", tk.END, values=(
                login.get('timestamp', 'N/A'),
                login.get('user', 'unknown'),
                login.get('ip', 'unknown'),
                status
            ))
    
    def update_warnings(self):
        """Update warnings tab with structured warning data"""
        tree = self.trees['warnings']
        tree.delete(*tree.get_children())
        
        warnings = self.analyzer.get_warnings()
        
        if not warnings:
            tree.insert("", tk.END, values=("No warnings", "-", "-", "-"))
            return
        
        for warning in warnings[:20]:
            # Determine source (IP or User)
            source = warning.get('ip', '') or warning.get('user', '')
            if not source:
                source = warning.get('details', 'No source')[:30]
            
            tree.insert("", tk.END, values=(
                warning.get('type', 'Unknown'),
                warning.get('severity', 'INFO'),
                source[:30],
                warning.get('timestamp', 'N/A')
            ))
    
    def update_summary(self):
        """Update summary tab with dynamic formatting"""
        summary = self.analyzer.get_summary()
        
        summary_text = f"""📊 ANALYSIS SUMMARY
{'='*50}

"""
        
        # Format summary sections
        if 'processing' in summary:
            summary_text += "📈 Statistics:\n"
            for key, value in summary['processing'].items():
                formatted_key = key.replace('_', ' ').title()
                summary_text += f"• {formatted_key}: {value}\n"
            summary_text += "\n"
        
        if 'login_analysis' in summary:
            summary_text += "🔐 Login Analysis:\n"
            for key, value in summary['login_analysis'].items():
                formatted_key = key.replace('_', ' ').title()
                summary_text += f"• {formatted_key}: {value}\n"
            summary_text += "\n"
        
        if 'security_warnings' in summary:
            summary_text += "🛡️ Security Warnings:\n"
            for key, value in summary['security_warnings'].items():
                formatted_key = key.replace('_', ' ').title()
                summary_text += f"• {formatted_key}: {value}\n"
            summary_text += "\n"
        
        # Show custom DS info
        if 'processing' in summary:
            summary_text += "🔧 Custom Data Structures:\n"
            summary_text += f"• IPs Tracked: {summary['processing'].get('custom_ds_ips_tracked', 0)}\n"
            summary_text += f"• Users Tracked: {summary['processing'].get('custom_ds_users_tracked', 0)}\n"
            summary_text += "\n"
        
        summary_text += f"⏰ Analysis time: {datetime.now().strftime('%H:%M:%S')}"
        
        self.update_text_widget(self.summary_text, summary_text)
    
    def update_alert_details(self):
        """Update alert details with structured warnings"""
        warnings = self.analyzer.get_warnings()
        
        if not warnings:
            self.update_text_widget(self.alert_text, "✅ No security alerts detected.")
            return
        
        # Show first warning details
        warning = warnings[0]
        alert_text = f"""⚠️ {warning.get('type', 'Unknown').replace('_', ' ').upper()}
{'═' * 60}

📅 Timestamp: {warning.get('timestamp', 'N/A')}
🛡️  Severity: {warning.get('severity', 'UNKNOWN')}
"""
        
        # Add source information
        if 'ip' in warning:
            alert_text += f"📍 IP Address: {warning['ip']}\n"
        if 'user' in warning:
            alert_text += f"👤 User: {warning['user']}\n"
        if 'attempt_count' in warning:
            alert_text += f"📊 Attempts: {warning['attempt_count']}\n"
        
        alert_text += f"""
📝 Details:
{'─' * 40}
{warning.get('details', 'No details')}

🛡️ Recommended Actions:
{'─' * 40}
{self.get_recommended_actions(warning)}
{'═' * 60}"""
        
        self.update_text_widget(self.alert_text, alert_text)
    
    def get_recommended_actions(self, warning):
        """Get recommended actions for warning type"""
        actions = {
            'brute_force_attack': "• Review failed login attempts\n• Consider IP blocking\n• Check for other suspicious activity",
            'multiple_failed_attempts': "• Verify user credentials\n• Check account security settings\n• Monitor user activity",
            'abnormal_hours_login': "• Verify user activity\n• Check if scheduled maintenance\n• Review access patterns",
            'critical_failure': "• Reset affected account\n• Investigate lockout cause\n• Review security policies",
            'suspicious_ip': "• Monitor IP activity\n• Consider temporary block\n• Check for related anomalies",
            'dictionary_attack': "• Block the attacking IP\n• Review failed user patterns\n• Implement rate limiting\n• Monitor for follow-up attacks",
            'credential_stuffing': "• Reset affected user's password\n• Check for credential breaches\n• Enable multi-factor authentication\n• Monitor for account takeover",
            'port_scanning':  "• Review firewall logs\n• Block scanning IP if persistent\n• Monitor for follow-up attacks\n• Consider intrusion detection system"
        }  
        
        warning_type = warning.get('type', '')
        return actions.get(warning_type, "• Investigate the anomaly\n• Review system logs\n• Update security policies")
    
    def show_failed_details(self, event):
        """Show failed login details"""
        tree = self.trees['failed']
        selection = tree.selection()
        if not selection:
            return
        
        values = tree.item(selection[0])['values']
        
        # Find matching log entry
        failed_logins = getattr(self.analyzer, 'failed_logins', [])
        if not failed_logins:
            failed_logins = self.analyzer.get_entries_by_type('failure')
        
        for login in failed_logins:
            if (login.get('timestamp') == values[0] and 
                login.get('user') == values[1] and 
                login.get('ip') == values[2]):
                
                details = self.format_login_details(login, "FAILED")
                self.update_text_widget(self.alert_text, details)
                break
    
    def show_success_details(self, event):
        """Show successful login details"""
        tree = self.trees['success']
        selection = tree.selection()
        if not selection:
            return
        
        values = tree.item(selection[0])['values']
        
        # Find matching log entry
        successful_logins = getattr(self.analyzer, 'successful_logins', [])
        if not successful_logins:
            successful_logins = self.analyzer.get_entries_by_type('success')
        
        for login in successful_logins:
            if (login.get('timestamp') == values[0] and 
                login.get('user') == values[1] and 
                login.get('ip') == values[2]):
                
                status = "⚠️  ABNORMAL HOURS" if values[3] == "Abnormal" else "✅ NORMAL"
                details = self.format_login_details(login, "SUCCESSFUL", status)
                self.update_text_widget(self.alert_text, details)
                break
    
    def show_warning_details(self, event):
        """Show warning details"""
        tree = self.trees['warnings']
        selection = tree.selection()
        if not selection:
            return
        
        values = tree.item(selection[0])['values']
        
        if values[0] == "No warnings":
            self.update_text_widget(self.alert_text, "✅ No security warnings detected.\nAll systems are normal.")
            return
        
        # Find matching warning
        warnings = self.analyzer.get_warnings()
        for warning in warnings:
            if (warning.get('type') == values[0] and 
                warning.get('timestamp') == values[3]):
                details = self.format_warning_details(warning)
                self.update_text_widget(self.alert_text, details)
                return   
        if warnings:
            details = self.format_warning_details(warnings[0])
            self.update_text_widget(self.alert_text, details)                 
    
    def format_login_details(self, login, login_type, status=""):
        """Format login details for display"""
        details = f"""🔴 {login_type} LOGIN DETAILS
{'═' * 60}

📅 Timestamp: {login.get('timestamp', 'N/A')}
👤 User: {login.get('user', 'unknown')}
📍 IP Address: {login.get('ip', 'unknown')}
"""
        if status:
            details += f"📊 Status: {status}\n"
        
        details += f"""
📝 Message:
{'─' * 40}
{login.get('message', 'No message')}
{'═' * 60}"""
        
        return details
    
    def format_warning_details(self, warning):
        """Format warning details for display"""
        details = f"""⚠️ {warning.get('type', 'Unknown').replace('_', ' ').upper()}
{'═' * 60}

📅 Timestamp: {warning.get('timestamp', 'N/A')}
🛡️  Severity: {warning.get('severity', 'INFO')}
"""
        
        if 'ip' in warning:
            details += f"📍 IP Address: {warning['ip']}\n"
        if 'user' in warning:
            details += f"👤 User: {warning['user']}\n"
        if 'attempt_count' in warning:
            details += f"📊 Attempts: {warning['attempt_count']}\n"
        
        details += f"""
📝 Details:
{'─' * 40}
{warning.get('details', 'No details')}

🛡️ Recommended Actions:
{'─' * 40}
{self.get_recommended_actions(warning)}
{'═' * 60}"""
        
        return details
    
    def export_report(self):
        """Export analysis report"""
        summary = self.analyzer.get_summary()
        
        if summary['processing']['total_lines'] == 0:
            messagebox.showwarning("No Data", "No analysis data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not file_path:
            return
        
        try:
            report = self.generate_report()
            
            with open(file_path, 'w') as f:
                f.write(report)
            
            self.status_var.set("Report exported")
            messagebox.showinfo("Success", "Report exported successfully")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def generate_report(self):
        """Generate report content"""
        summary = self.analyzer.get_summary()
        warnings = self.analyzer.get_warnings()
        
        report_lines = [
            "="*50,
            "SECURITY LOG ANALYSIS REPORT",
            "="*50,
            "",
            f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"File analyzed: {self.current_file or 'No file'}",
            ""
        ]
        
        # Add summary sections
        for section_title, section_key in [('STATISTICS', 'processing'), 
                                          ('LOGIN ANALYSIS', 'login_analysis')]:
            if section_key in summary:
                report_lines.append(f"{section_title}:")
                for key, value in summary[section_key].items():
                    formatted_key = key.replace('_', ' ').title()
                    report_lines.append(f"  {formatted_key}: {value}")
                report_lines.append("")
        
        # Add warnings
        report_lines.append("SECURITY WARNINGS:")
        if warnings:
            for warning in warnings:
                report_lines.append(f"  • [{warning.get('severity', 'INFO')}] {warning.get('details', 'No details')}")
        else:
            report_lines.append("  No security warnings detected.")
        
        report_lines.append("")
        report_lines.append("="*50)
        
        return '\n'.join(report_lines)
    
    def clear_data(self):
        """Clear all data"""
        if not messagebox.askyesno("Confirm", "Clear all analysis data?"):
            return
        
        self.analyzer.reset()
        self.current_file = None
        
        # Clear all treeviews
        for tree in self.trees.values():
            tree.delete(*tree.get_children())
        
        # Clear all text widgets
        for widget in [self.log_text, self.summary_text, self.alert_text]:
            self.update_text_widget(widget, "")
        
        self.file_label.config(text="📁 No file loaded")
        self.status_var.set("All data cleared")
        messagebox.showinfo("Cleared", "All data has been cleared")

def main():
    """Main function"""
    root = tk.Tk()
    app = AuthLogAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()