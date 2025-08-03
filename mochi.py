import psutil
import time
from datetime import datetime
from colorama import Fore, init
from pyfiglet import Figlet

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

def log_detection(proc, keyword):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(Fore.RED + f"\n⚠️ [{now}] Suspicious process detected!")
    print(Fore.LIGHTWHITE_EX + f"🧠 PID: {proc.pid}")
    print(f"📌 Name: {proc.name()}")
    print(Fore.YELLOW + f"💣 Trigger Word: {keyword}")

    # Attempt to kill it
    try:
        proc.kill()
        proc.wait(timeout=3)
        print(Fore.GREEN + f"✅ Process {proc.pid} killed successfully!\n" + Fore.CYAN + "-"*40)
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        reason = explain_kill_failure(e, proc)
        print(Fore.LIGHTRED_EX + f"❌ Could not kill process {proc.pid}")
        print(Fore.RED + f"🔎 Reason: {reason}\n" + Fore.CYAN + "-"*40)

def check_new_processes():
    global seen_pids
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if proc.info['pid'] not in seen_pids:
            seen_pids.add(proc.info['pid'])
            try:
                cmdline_list = proc.info.get('cmdline')
                if isinstance(cmdline_list, list):
                    cmdline = ' '.join(cmdline_list).lower()
                    for word in DANGER_KEYWORDS:
                        if word in cmdline:
                            log_detection(proc, word)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

def monitor():
    print(Fore.LIGHTMAGENTA_EX + "🍡 Mochi Background Watcher Started (Press Ctrl+C to stop)\n")
    try:
        while True:
            check_new_processes()
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n🌸 Mochi Stopped. Bye Bye!")

def show_banner():
    banner = Figlet(font="slant")
    print(Fore.LIGHTMAGENTA_EX + banner.renderText("Mochi"))
    print(Fore.CYAN + "🍡 Mochi Suspicious Background Watcher Started!")
    print(Fore.YELLOW + "🌸 Watching silently and terminating threats...\n")

if __name__ == "__main__":
    show_banner()
    monitor()
