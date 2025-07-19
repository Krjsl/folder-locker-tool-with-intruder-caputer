import os
import cv2
import json
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk, scrolledtext
from ttkthemes import ThemedStyle

# === PATH SETUP ===
LOG_FOLDER = "Security_Logs"
LOCK_INFO_FILE = "lock_info.json"
LOG_FILE = os.path.join(LOG_FOLDER, "access_log.txt")
os.makedirs(LOG_FOLDER, exist_ok=True)

# === Helper Functions ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def take_photo():
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(LOG_FOLDER, f"attempt_{timestamp}.jpg")
        cv2.imwrite(filename, frame)
    cam.release()

def log_attempt(folder=None, success=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"
    username = os.getlogin()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] [{username}] {status} login attempt")
        if folder:
            f.write(f" on folder: {folder}")
        f.write("\n")

def load_locks():
    if not os.path.exists(LOCK_INFO_FILE):
        return {}
    with open(LOCK_INFO_FILE, "r") as f:
        return json.load(f)

def save_locks(data):
    with open(LOCK_INFO_FILE, "w") as f:
        json.dump(data, f)

def lock_folder(folder):
    os.system(f'attrib +h +s "{folder}"')
    os.system(f'icacls "{folder}" /deny Everyone:(OI)(CI)F')

def unlock_folder_permissions(folder):
    os.system(f'icacls "{folder}" /grant Everyone:(OI)(CI)F')
    os.system(f'attrib -h -s "{folder}"')

# === GUI FUNCTIONS ===
def gui_set_lock():
    folder = filedialog.askdirectory(title="Select Folder to Lock")
    if not folder:
        return

    locks = load_locks()
    if folder in locks:
        messagebox.showwarning("Already Locked", "This folder is already locked.")
        return

    pwd1 = simpledialog.askstring("Set Password", "Enter a password:", show="*")
    pwd2 = simpledialog.askstring("Confirm Password", "Confirm the password:", show="*")
    if not pwd1 or pwd1 != pwd2:
        messagebox.showerror("Mismatch", "Passwords do not match.")
        return

    hashed_pwd = hash_password(pwd1)
    locks[folder] = hashed_pwd
    save_locks(locks)

    lock_folder(folder)
    messagebox.showinfo("✅ Success", "Folder locked successfully!")

def gui_unlock_folder():
    locks = load_locks()
    if not locks:
        messagebox.showinfo("No Locks", "There are no locked folders.")
        return

    unlock_window = tk.Toplevel(root)
    unlock_window.title("🔓 Unlock Folder")
    unlock_window.geometry("500x300")
    unlock_window.resizable(False, False)
    unlock_window.configure(bg="#1e1e1e")

    tk.Label(unlock_window, text="Select a folder to unlock:", font=("Segoe UI", 12), bg="#1e1e1e", fg="white").pack(pady=10)

    folder_var = tk.StringVar()
    folder_list = ttk.Combobox(unlock_window, textvariable=folder_var, width=60, state="readonly")
    folder_list['values'] = list(locks.keys())
    folder_list.pack(pady=10)

    def attempt_unlock():
        folder = folder_var.get()
        if not folder:
            messagebox.showwarning("No Selection", "Please select a folder.")
            return

        stored_hash = locks[folder]
        attempts = 0
        MAX_ATTEMPTS = 3

        while attempts < MAX_ATTEMPTS:
            pwd = simpledialog.askstring("Password", "Enter password to unlock:", show="*", parent=unlock_window)
            if pwd is None:
                return
            if hash_password(pwd) == stored_hash:
                unlock_folder_permissions(folder)
                log_attempt(folder=folder, success=True)
                del locks[folder]
                save_locks(locks)
                messagebox.showinfo("✅ Access Granted", "Folder unlocked successfully.")
                unlock_window.destroy()
                os.startfile(folder)
                return
            else:
                attempts += 1
                log_attempt(folder=folder, success=False)

        take_photo()
        messagebox.showerror("⚠️ Security Alert!", "Unauthorized access detected. Photo captured.")
        unlock_window.destroy()

    ttk.Button(unlock_window, text="🔓 Unlock Selected Folder", command=attempt_unlock).pack(pady=15)

def gui_view_logs():
    if not os.path.exists(LOG_FILE):
        messagebox.showinfo("Log File", "No log entries found.")
        return

    log_win = tk.Toplevel(root)
    log_win.title("📜 Access Logs")
    log_win.geometry("600x400")
    log_win.resizable(True, True)
    log_win.configure(bg="#1e1e1e")

    text_area = scrolledtext.ScrolledText(log_win, wrap=tk.WORD, width=80, height=20, bg="#f4f4f4", font=("Consolas", 10))
    text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    with open(LOG_FILE, "r") as f:
        text_area.insert(tk.END, f.read())

    text_area.configure(state='disabled')

# === Main Folder Locker GUI ===
def launch_main_gui():
    global root
    root = tk.Tk()
    root.title("🔐 Folder Locker Tool")
    root.geometry("500x450")
    root.resizable(False, False)
    root.configure(bg="#1e1e1e")

    style = ThemedStyle(root)
    style.set_theme("arc")

    title_font = ("Segoe UI", 20, "bold")
    button_font = ("Segoe UI", 12, "bold")

    tk.Label(root, text="🔐 Secure Folder Locker", font=title_font, fg="#00ffff", bg="#1e1e1e").pack(pady=30)

    ttk.Style().configure("TButton", font=button_font, padding=10)

    ttk.Button(root, text="🔒 Lock Folder", width=30, command=gui_set_lock).pack(pady=15)
    ttk.Button(root, text="🔓 Unlock Folder", width=30, command=gui_unlock_folder).pack(pady=10)
    ttk.Button(root, text="📜 View Logs", width=30, command=gui_view_logs).pack(pady=10)

    tk.Label(root, text="By Krijal Prajapati", fg="gray", font=("Arial", 10), bg="#1e1e1e").pack(side="bottom", pady=15)

    root.mainloop()

# === Welcome Page ===
def show_welcome_page():
    welcome = tk.Tk()
    welcome.title("Welcome")
    welcome.geometry("500x300")
    welcome.configure(bg="#292929")
    welcome.resizable(False, False)

    tk.Label(welcome, text="🔐 Welcome to", font=("Segoe UI", 16), bg="#292929", fg="#f0f0f0").pack(pady=(30, 0))
    tk.Label(welcome, text="Secure Folder Locker", font=("Segoe UI", 22, "bold"), bg="#292929", fg="#00ffff").pack(pady=(5, 20))

    def start_app():
        welcome.destroy()
        launch_main_gui()

    def exit_app():
        welcome.destroy()

    ttk.Button(welcome, text="🚀 Start", width=25, command=start_app).pack(pady=10)
    ttk.Button(welcome, text="❌ Exit", width=25, command=exit_app).pack(pady=5)

    tk.Label(welcome, text="© 2025 by Krijal", bg="#292929", fg="gray", font=("Arial", 9)).pack(side="bottom", pady=10)

    welcome.mainloop()

# === Entry Point ===
if __name__ == "__main__":
    show_welcome_page()
