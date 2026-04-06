import psutil
import time
from datetime import datetime
from colorama import Fore, init
from pyfiglet import Figlet
import tkinter as tk
import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageTk

init(autoreset=True)

# 🎯 Suspicious terms to watch and kill
DANGER_KEYWORDS = [
    "nc", "netcat", "ncat", "bash -i", "sh -i", "dash -i", "python -c", "perl -e", "ruby -e",
    "lua -e", "node -e", "msf", "msfvenom", "meterpreter", "reverse", "bind", "shell",
    "cmd.exe", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32",
    "svchost", "wininit", "taskhostw", "schtasks", "at.exe", "sc.exe", "explorer.exe",
    "services.exe", "lsass.exe", "lsm.exe", "conhost", "smss.exe", "winlogon.exe", "dllhost",
    "svhost", "sshd", "dropbear", "telnet", "ftp", "wget", "curl", "tftp", "scp", "sftp",
    "socat", "nmap", "hping", "masscan", "zmap", "dirb", "dirbuster", "hydra", "medusa",
    "john", "hashcat", "mimikatz", "secretsdump", "enum4linux", "smbclient", "impacket",
    "evil-winrm", "responder", "dnsspoof", "arpspoof", "ettercap", "wireshark", "tcpdump",
    "airmon-ng", "airodump-ng", "aircrack-ng", "mshta", "powersploit", "empire", "nishang",
    "covenant", "quasar", "revshell", "backdoor", "persistence", "keylogger", "keylog",
    "screenshot", "remote desktop", "rdp", "vnc", "xrdp", "teamviewer", "anydesk", "ngrok",
    "serveo", "localtunnel", "dnscat", "frp", "c2", "command and control"
]

seen_pids = set()
all_results = []
monitoring = False

def explain_kill_failure(e, proc):
    """Return a human-readable reason for failure."""
    if isinstance(e, psutil.AccessDenied):
        return "Access Denied (System or Admin-level process)"
    elif isinstance(e, psutil.NoSuchProcess):
        return "Process already terminated"
    else:
        try:
            if proc.username() == 'root' or proc.username().lower() in ["system", "administrator"]:
                return "System-critical or root process"
        except:
            pass
        return f"Unknown error: {str(e)}"

def check_new_processes(log_callback, progress_callback):
    global seen_pids, all_results
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if proc.info['pid'] not in seen_pids:
            seen_pids.add(proc.info['pid'])
            try:
                cmdline_list = proc.info.get('cmdline')
                if isinstance(cmdline_list, list):
                    cmdline = ' '.join(cmdline_list).lower()
                    for word in DANGER_KEYWORDS:
                        if word in cmdline:
                            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            result = {
                                "time": now,
                                "pid": proc.pid,
                                "name": proc.name(),
                                "keyword": word,
                                "killed": False,
                                "reason": ""
                            }
                            # Attempt to kill
                            try:
                                proc.kill()
                                proc.wait(timeout=3)
                                result["killed"] = True
                                log_callback(result, "green")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                                reason = explain_kill_failure(e, proc)
                                result["reason"] = reason
                                log_callback(result, "red")
                            all_results.append(result)
                            progress_callback(50)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

def monitor_background(log_callback, progress_callback):
    global monitoring
    while monitoring:
        check_new_processes(log_callback, progress_callback)
        time.sleep(2)

# ================= PROFESSIONAL GUI ================= #
class MochiGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Mochi Background Watcher")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        self.cute_font = ("Comic Sans MS", 14)
        self.prof_font = ("Arial", 12)
        self.monitoring = False
        self.filtered = False  # Track filter state
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(root, width=250, corner_radius=15)
        self.sidebar.pack(side="left", fill="y", padx=15, pady=15)
        
        # Logo
        try:
            logo_img = Image.open("logo.png").resize((120, 120))
            self.logo = ImageTk.PhotoImage(logo_img)
            logo_label = ctk.CTkLabel(self.sidebar, image=self.logo, text="")
            logo_label.pack(pady=15)
        except:
            pass
        
        # Sidebar Buttons
        self.start_button = ctk.CTkButton(self.sidebar, text="▶️ Start Monitoring", command=self.start_monitoring, fg_color="green", hover_color="lightgreen", corner_radius=25)
        self.start_button.pack(pady=15)
        
        self.stop_button = ctk.CTkButton(self.sidebar, text="⏹️ Stop Monitoring", command=self.stop_monitoring, fg_color="red", hover_color="darkred", corner_radius=25, state="disabled")
        self.stop_button.pack(pady=15)
        
        self.continue_button = ctk.CTkButton(self.sidebar, text="▶️ Continue Monitoring", command=self.continue_monitoring, fg_color="blue", hover_color="lightblue", corner_radius=25, state="disabled")
        self.continue_button.pack(pady=15)
        
        self.export_button = ctk.CTkButton(self.sidebar, text="Export Results", command=self.export_results, fg_color="blue", corner_radius=25)
        self.export_button.pack(pady=15)
        
        self.exit_button = ctk.CTkButton(self.sidebar, text="Exit", command=root.quit, fg_color="red", hover_color="pink", corner_radius=25)
        self.exit_button.pack(pady=15)
        
        # Main Frame
        self.main_frame = ctk.CTkFrame(root, corner_radius=15)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=15, pady=15)
        
        # Tabs
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Overall Results Tab (Table Like Picklu)
        self.results_tab = self.tabview.add("📊 Overall Results")
        self.tree = ttk.Treeview(self.results_tab, columns=("Time", "PID", "Name", "Trigger Word", "Kill Status/Reason"), show="headings", height=20)
        self.tree.pack(fill="both", expand=True, padx=15, pady=15)
        self.tree.heading("Time", text="Time")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Trigger Word", text="Trigger Word")
        self.tree.heading("Kill Status/Reason", text="Kill Status/Reason")
        self.tree.column("Time", width=150)
        self.tree.column("PID", width=80)
        self.tree.column("Name", width=150)
        self.tree.column("Trigger Word", width=150)
        self.tree.column("Kill Status/Reason", width=200)
        # Style for colors
        self.tree.tag_configure("green", background="lightgreen")
        self.tree.tag_configure("red", background="lightcoral")
        self.tree.tag_configure("info", background="lightblue")
        
        # Detailed Logs Tab
        self.logs_tab = self.tabview.add("Detailed Logs")
        self.logs_text = ctk.CTkTextbox(self.logs_tab, wrap="word", font=self.prof_font)
        self.logs_text.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Progress & Status
        self.progress = ctk.CTkProgressBar(self.main_frame, width=700, corner_radius=15)
        self.progress.pack(pady=15)
        self.progress.set(0)
        
        self.status_label = ctk.CTkLabel(self.main_frame, text="Ready to monitor! 🍡")
        self.status_label.pack(pady=10)
        
        # Spinner
        self.spinner = ctk.CTkLabel(self.main_frame, text="⏳", font=("Arial", 24))
        self.spinner.pack(pady=10)
        self.spinner.pack_forget()
    
    def log(self, result, tag="info"):
        # Add to table
        status = "Killed successfully" if result["killed"] else f"Failed: {result['reason']}"
        self.tree.insert("", "end", values=(result["time"], result["pid"], result["name"], result["keyword"], status), tags=(tag,))
        
        # Also log to detailed logs
        self.logs_text.insert("end", f"[{result['time']}] PID {result['pid']} ({result['name']}) - Trigger: {result['keyword']} - {status}\n")
        self.logs_text.see("end")
    
    def update_progress(self, value):
        self.progress.set(value / 100)
    
    def start_monitoring(self):
        global monitoring
        if monitoring:
            messagebox.showwarning("Monitoring", "Already monitoring! 😅")
            return
        monitoring = True
        self.monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.continue_button.configure(state="disabled")
        self.status_label.configure(text="Monitoring started... 🔍")
        self.spinner.pack(pady=10)
        threading.Thread(target=monitor_background, args=(self.log, self.update_progress), daemon=True).start()
    
    def stop_monitoring(self):
        global monitoring
        monitoring = False
        self.monitoring = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.continue_button.configure(state="normal")
        self.status_label.configure(text="Monitoring stopped! 🛑")
        self.spinner.pack_forget()
    
    def continue_monitoring(self):
        global monitoring
        if monitoring:
            messagebox.showwarning("Monitoring", "Already monitoring! 😅")
            return
        monitoring = True
        self.monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.continue_button.configure(state="disabled")
        self.status_label.configure(text="Continuing monitoring... 🔄")
        self.spinner.pack(pady=10)
        threading.Thread(target=monitor_background, args=(self.log, self.update_progress), daemon=True).start()
    
    def filter_dangers(self):
        self.filtered = True
        self.filter_button.pack_forget()
        self.show_all_button.pack(pady=15)
        for item in self.tree.get_children():
            self.tree.delete(item)
        for res in all_results:
            if res["killed"] or res["reason"]:
                tag = "green" if res["killed"] else "red"
                status = "Killed successfully" if res["killed"] else f"Failed: {res['reason']}"
                self.tree.insert("", "end", values=(res["time"], res["pid"], res["name"], res["keyword"], status), tags=(tag,))
    
    def show_all_results(self):
        self.filtered = False
        self.show_all_button.pack_forget()
        self.filter_button.pack(pady=15)
        for item in self.tree.get_children():
            self.tree.delete(item)
        for res in all_results:
            tag = "green" if res["killed"] else "red" if res["reason"] else "info"
            status = "Killed successfully" if res["killed"] else f"Failed: {res['reason']}" if res["reason"] else "Detected"
            self.tree.insert("", "end", values=(res["time"], res["pid"], res["name"], res["keyword"], status), tags=(tag,))
    
    def export_results(self):
        content = ""
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            content += f"{values[0]} | {values[1]} | {values[2]} | {values[3]} | {values[4]}\n"
        if not content:
            messagebox.showwarning("No Results", "No results to export! 😟")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write("Time | PID | Name | Trigger Word | Kill Status/Reason\n" + content)
            messagebox.showinfo("Exported", "Results exported! 📄")

# ================= MAIN ================= #
if __name__ == "__main__":
    root = ctk.CTk()
    app = MochiGUI(root)
    root.mainloop()
