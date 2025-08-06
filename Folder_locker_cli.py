import os
import json
import getpass
import hashlib
import subprocess
import time
from datetime import datetime
import cv2

# === CONFIGURATION ===
LOCK_INFO_FILE = "lock_info.json"
LOG_FOLDER = "Security_Logs"

os.makedirs(LOG_FOLDER, exist_ok=True)

# === Utility Functions ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_locks():
    if not os.path.exists(LOCK_INFO_FILE):
        return {}
    with open(LOCK_INFO_FILE, "r") as f:
        return json.load(f)

def save_locks(data):
    with open(LOCK_INFO_FILE, "w") as f:
        json.dump(data, f, indent=4)

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logfile = os.path.join(LOG_FOLDER, "login_attempts.log")
    with open(logfile, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def take_photo():
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    if ret:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(LOG_FOLDER, f"unauth_cli_{timestamp}.jpg")
        cv2.imwrite(filename, frame)
        print(f"[📸] Photo captured: {filename}")
    else:
        print("[❌] Webcam access failed.")
    cam.release()

# === Lock & Unlock Functions ===
def set_lock():
    folder = input("Enter full path of folder to lock: ").strip()
    if not os.path.isdir(folder):
        print("[❌] Invalid folder path.")
        return

    locks = load_locks()
    if folder in locks:
        print("[⚠️] Folder already locked.")
        return

    pwd1 = getpass.getpass("Set password: ")
    pwd2 = getpass.getpass("Confirm password: ")
    if pwd1 != pwd2:
        print("[❌] Passwords do not match.")
        return

    # Lock using attrib and icacls
    os.system(f'attrib +h +s "{folder}"')
    os.system(f'icacls "{folder}" /deny Everyone:(OI)(CI)F')

    locks[folder] = hash_password(pwd1)
    save_locks(locks)

    print("[✅] Folder locked and hidden successfully.")

def unlock_folder():
    locks = load_locks()
    if not locks:
        print("[❌] No folders are currently locked.")
        return

    print("\nLocked folders:")
    for i, folder in enumerate(locks.keys()):
        print(f"{i+1}. {folder}")
    try:
        choice = int(input("Choose a folder to unlock: ")) - 1
        folder = list(locks.keys())[choice]
    except:
        print("[❌] Invalid selection.")
        return

    stored_hash = locks[folder]
    attempts = 3

    while attempts > 0:
        pwd = getpass.getpass("Enter password: ")
        if hash_password(pwd) == stored_hash:
            os.system(f'icacls "{folder}" /grant Everyone:(OI)(CI)F')
            os.system(f'attrib -h -s "{folder}"')

            print("[✅] Folder unlocked successfully.")
            log_event(f"SUCCESSFUL unlock for folder '{folder}'")
            del locks[folder]
            save_locks(locks)
            subprocess.Popen(f'explorer "{folder}"')
            return
        else:
            attempts -= 1
            print(f"[❌] Incorrect password. Attempts left: {attempts}")
            log_event(f"FAILED unlock attempt for folder '{folder}'")

    print("🚨 Unauthorized access attempt detected!")
    log_event(f"UNAUTHORIZED access attempt for folder '{folder}'")
    take_photo()

# === Entry Point ===
def main():
    while True:
        print("\n📁 Folder Locker CLI")
        print("1. Lock Folder")
        print("2. Unlock Folder")
        print("3. Exit")
        choice = input("Choose option: ")

        if choice == "1":
            set_lock()
        elif choice == "2":
            unlock_folder()
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("[❌] Invalid option.")

if __name__ == "__main__":
    main()
