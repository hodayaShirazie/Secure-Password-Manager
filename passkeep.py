# # !/usr/bin/python3
# import hashlib, os, sys, shutil, random, string
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import customtkinter as ctk
# import tkinter as tk
# from tkinter import ttk, messagebox, simpledialog
#
# ctk.set_appearance_mode("Dark")  # Dark / Light
# ctk.set_default_color_theme("blue")  # blue, dark-blue, green
#
#
# class PasswordManagerGUI:
#     def __init__(self):
#         # חלון ראשי
#         self.root = ctk.CTk()
#         self.root.geometry("600x500")
#         self.root.title("Password Manager")
#
#         # בדיקת בסיס נתונים
#         try:
#             db_handle = open("passwords.db", "rb")
#             self.path_to_database = "passwords.db"
#         except:
#             messagebox.showinfo(title="Database", message="'passwords.db' not found. Creating new database.")
#             self.path_to_database = self.check_database()
#             db_handle = open(self.path_to_database, "rb")
#
#         self.db_key_hash = db_handle.read(64).decode()
#         self.ciphertext = db_handle.read()
#
#         # בקשת סיסמה
#         for _ in range(3):
#             key = simpledialog.askstring("Decryption Key", "Enter decryption key:", show="*")
#             if key is None:
#                 sys.exit()
#             self.decryption_key = self.pad_db_key(key)
#             password_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
#             if self.db_key_hash == password_hash:
#                 db_handle.close()
#                 self.decrypt_db()
#                 break
#             else:
#                 messagebox.showerror(title="Error", message="Incorrect password")
#         else:
#             messagebox.showerror(title="Error", message="Too many failed attempts")
#             sys.exit()
#
#         self.build_main_window()
#         self.root.mainloop()
#
#     # ---------------- פונקציות בסיסיות ----------------
#     def pad_db_key(self, password):
#         if len(password) % 16 == 0: return password
#         return password + ("0" * (16 - (len(password) % 16)))
#
#     def check_database(self):
#         path_to_database = "passwords.db"
#         db_handle = open(path_to_database, "wb")
#         default_pass = hashlib.sha256(self.pad_db_key("password123").encode()).hexdigest()
#         db_handle.write(default_pass.encode())
#         db_handle.close()
#         messagebox.showinfo(title="Database", message="Default decryption key is 'password123'")
#         return path_to_database
#
#     def decrypt_db(self):
#         if len(self.ciphertext.strip()) != 0:
#             aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
#             self.content = unpad(aes.decrypt(self.ciphertext), AES.block_size).decode()
#             self.records_count = len(self.content.split("|"))
#         else:
#             self.content = ""
#             self.records_count = 0
#
#     def save_db(self):
#         db_handle = open(self.path_to_database, "wb")
#         ciphertext = b""
#         if self.records_count != 0:
#             aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
#             ciphertext = aes.encrypt(pad(self.content.encode(), AES.block_size))
#         db_handle.write(self.db_key_hash.encode() + ciphertext)
#         db_handle.close()
#
#     def find_record(self, record_id):
#         records = [r.split("-") for r in self.content.split("|")]
#         for i, r in enumerate(records):
#             if int(r[0]) == record_id:
#                 return i
#         return None
#
#     # ---------------- GUI משודרג ----------------
#     def build_main_window(self):
#         frame = ctk.CTkFrame(self.root)
#         frame.pack(pady=20, padx=20, fill="both", expand=True)
#
#         btns = [
#             ("Show Credentials", self.show_credentials_gui),
#             ("Add Credentials", self.add_credentials_gui),
#             ("Edit Credentials", self.edit_credentials_gui),
#             ("Delete Credentials", self.delete_credentials_gui),
#             ("Change DB Password", self.change_db_password_gui),
#             ("Generate Password", self.generate_password_gui),
#             ("Backup Database", self.backup_database_gui),
#             ("Erase Database", self.erase_database_gui),
#             ("Exit", self.root.destroy)
#         ]
#
#         for text, cmd in btns:
#             b = ctk.CTkButton(frame, text=text, command=cmd, width=250, height=40, fg_color="#3b82f6",
#                               hover_color="#2563eb")
#             b.pack(pady=8)
#
#     # ------------------- Show Credentials -------------------
#     def show_credentials_gui(self):
#         if self.records_count == 0:
#             messagebox.showinfo(title="Info", message="No records found")
#             return
#
#         top = ctk.CTkToplevel(self.root)
#         top.title("Credentials")
#         top.geometry("600x300")
#
#         columns = ("ID", "Username/Email", "Password", "Platform")
#         tree = ttk.Treeview(top, columns=columns, show="headings")
#         for col in columns:
#             tree.heading(col, text=col)
#             tree.column(col, width=140)
#         tree.pack(fill="both", expand=True)
#
#         for record in self.content.split("|"):
#             tree.insert("", tk.END, values=record.split("-"))
#
#     # ------------------- Add Credentials -------------------
#     def add_credentials_gui(self):
#         if self.records_count is None: self.records_count = 0
#         top = ctk.CTkToplevel(self.root)
#         top.title("Add Credential")
#         top.geometry("300x250")
#
#         labels = ["Username/Email", "Password", "Retype Password", "Platform"]
#         entries = []
#
#         for l in labels:
#             ctk.CTkLabel(top, text=l).pack()
#             e = ctk.CTkEntry(top, show="*" if "Password" in l else "")
#             e.pack()
#             entries.append(e)
#
#         def save_record():
#             username, pwd1, pwd2, platform = [e.get() for e in entries]
#             if pwd1 != pwd2:
#                 messagebox.showerror(title="Error", message="Passwords do not match")
#                 return
#             new_id = 1 if self.records_count == 0 else int(self.content.split("|")[-1].split("-")[0]) + 1
#             new_record = f"{new_id}-{username}-{pwd1}-{platform}"
#             self.content = new_record if self.records_count == 0 else self.content + "|" + new_record
#             self.records_count += 1
#             self.save_db()
#             messagebox.showinfo(title="Success", message="Record added")
#             top.destroy()
#
#         ctk.CTkButton(top, text="Save", command=save_record, width=100).pack(pady=10)
#
#     # ------------------- Edit Credentials -------------------
#     def edit_credentials_gui(self):
#         if self.records_count == 0:
#             messagebox.showinfo(title="Info", message="No records to edit")
#             return
#         record_id = simpledialog.askinteger("Edit Record", "Enter record ID to edit:")
#         if record_id is None:
#             return
#         idx = self.find_record(record_id)
#         if idx is None:
#             messagebox.showerror(title="Error", message="Record not found")
#             return
#         records = [r.split("-") for r in self.content.split("|")]
#         top = ctk.CTkToplevel(self.root)
#         top.title("Edit Credential")
#         top.geometry("300x200")
#         fields = ["Username/Email", "Password", "Platform"]
#         entries = []
#         for i, field in enumerate(fields):
#             ctk.CTkLabel(top, text=field).pack()
#             e = ctk.CTkEntry(top)
#             e.insert(0, records[idx][i + 1])
#             e.pack()
#             entries.append(e)
#
#         def save_edit():
#             for i, e in enumerate(entries):
#                 records[idx][i + 1] = e.get()
#             self.content = "|".join(["-".join(r) for r in records])
#             self.save_db()
#             messagebox.showinfo(title="Success", message="Record updated")
#             top.destroy()
#
#         ctk.CTkButton(top, text="Save", command=save_edit).pack(pady=10)
#
#     # ------------------- Delete Credentials -------------------
#     def delete_credentials_gui(self):
#         if self.records_count == 0:
#             messagebox.showinfo(title="Info", message="No records to delete")
#             return
#         record_id = simpledialog.askinteger("Delete Record", "Enter record ID to delete:")
#         if record_id is None:
#             return
#         idx = self.find_record(record_id)
#         if idx is None:
#             messagebox.showerror(title="Error", message="Record not found")
#             return
#         if messagebox.askyesno("Confirm", "Are you sure you want to delete this record?"):
#             records = self.content.split("|")
#             del records[idx]
#             self.records_count -= 1
#             self.content = "|".join(records) if self.records_count != 0 else ""
#             self.save_db()
#             messagebox.showinfo(title="Deleted", message="Record deleted")
#
#     # ------------------- Change DB Password -------------------
#     def change_db_password_gui(self):
#         current = simpledialog.askstring("Current Key", "Enter current decryption key:", show="*")
#         if current is None:
#             return
#         if hashlib.sha256(self.pad_db_key(current).encode()).hexdigest() != self.db_key_hash:
#             messagebox.showerror(title="Error", message="Incorrect current key")
#             return
#         new = simpledialog.askstring("New Key", "Enter new decryption key (>=10 chars):")
#         if new is None or len(new) < 10:
#             messagebox.showerror(title="Error", message="Password too short")
#             return
#         confirm = simpledialog.askstring("Confirm", "Confirm new decryption key:")
#         if new != confirm:
#             messagebox.showerror(title="Error", message="Passwords do not match")
#             return
#         self.decryption_key = self.pad_db_key(new)
#         self.db_key_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
#         self.save_db()
#         messagebox.showinfo(title="Success", message="Database password updated")
#
#     # ------------------- Generate Password -------------------
#     def generate_password_gui(self):
#         password = "".join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
#         messagebox.showinfo(title="Generated Password", message=password)
#
#     # ------------------- Backup / Erase -------------------
#     def backup_database_gui(self):
#         shutil.copyfile(self.path_to_database, "./passwords.db.bak")
#         messagebox.showinfo(title="Backup", message="Database backup created")
#
#     def erase_database_gui(self):
#         if messagebox.askyesno("Confirm", "Are you sure you want to erase the database?"):
#             self.content = ""
#             self.records_count = 0
#             self.save_db()
#             messagebox.showinfo(title="Erased", message="Database erased")
#
#
# # -------------------- הפעלת התוכנית --------------------
# if __name__ == "__main__":
#     PasswordManagerGUI()






#!/usr/bin/python3
import sqlite3
import random
import string
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# -------------------- DB Functions --------------------
DB_NAME = "passwords.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        platform TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def add_credential(username, password, platform):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (username, password, platform) VALUES (?, ?, ?)",
                   (username, password, platform))
    conn.commit()
    conn.close()

def get_all_credentials():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM credentials")
    rows = cursor.fetchall()
    conn.close()
    return rows

def edit_credential(record_id, new_username=None, new_password=None, new_platform=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    if new_username:
        cursor.execute("UPDATE credentials SET username=? WHERE id=?", (new_username, record_id))
    if new_password:
        cursor.execute("UPDATE credentials SET password=? WHERE id=?", (new_password, record_id))
    if new_platform:
        cursor.execute("UPDATE credentials SET platform=? WHERE id=?", (new_platform, record_id))
    conn.commit()
    conn.close()

def delete_credential(record_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM credentials WHERE id=?", (record_id,))
    conn.commit()
    conn.close()


# -------------------- GUI Class --------------------
class PasswordManagerGUI:
    def __init__(self):
        init_db()
        self.root = ctk.CTk()
        self.root.geometry("600x500")
        self.root.title("Password Manager")
        self.build_main_window()
        self.root.mainloop()

    # -------------------- GUI Main Window --------------------
    def build_main_window(self):
        frame = ctk.CTkFrame(self.root)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        btns = [
            ("Show Credentials", self.show_credentials_gui),
            ("Add Credential", self.add_credentials_gui),
            ("Edit Credential", self.edit_credentials_gui),
            ("Delete Credential", self.delete_credentials_gui),
            ("Generate Password", self.generate_password_gui),
            ("Exit", self.root.destroy)
        ]

        for text, cmd in btns:
            b = ctk.CTkButton(frame, text=text, command=cmd, width=250, height=40, fg_color="#3b82f6", hover_color="#2563eb")
            b.pack(pady=8)

    # -------------------- Show Credentials --------------------
    def show_credentials_gui(self):
        rows = get_all_credentials()
        if not rows:
            messagebox.showinfo(title="Info", message="No records found")
            return

        top = ctk.CTkToplevel(self.root)
        top.title("Credentials")
        top.geometry("600x300")

        columns = ("ID", "Username/Email", "Password", "Platform")
        tree = ttk.Treeview(top, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=140)
        tree.pack(fill="both", expand=True)

        for record in rows:
            tree.insert("", tk.END, values=record)

    # -------------------- Add Credential --------------------
    def add_credentials_gui(self):
        top = ctk.CTkToplevel(self.root)
        top.title("Add Credential")
        top.geometry("300x250")

        labels = ["Username/Email", "Password", "Retype Password", "Platform"]
        entries = []

        for l in labels:
            ctk.CTkLabel(top, text=l).pack()
            e = ctk.CTkEntry(top, show="*" if "Password" in l else "")
            e.pack()
            entries.append(e)

        def save_record():
            username, pwd1, pwd2, platform = [e.get() for e in entries]
            if pwd1 != pwd2:
                messagebox.showerror(title="Error", message="Passwords do not match")
                return
            add_credential(username, pwd1, platform)
            messagebox.showinfo(title="Success", message="Record added")
            top.destroy()

        ctk.CTkButton(top, text="Save", command=save_record, width=100).pack(pady=10)

    # -------------------- Edit Credential --------------------
    def edit_credentials_gui(self):
        rows = get_all_credentials()
        if not rows:
            messagebox.showinfo(title="Info", message="No records to edit")
            return
        record_id = simpledialog.askinteger("Edit Record", "Enter record ID to edit:")
        if record_id is None:
            return
        record = next((r for r in rows if r[0] == record_id), None)
        if record is None:
            messagebox.showerror(title="Error", message="Record not found")
            return

        top = ctk.CTkToplevel(self.root)
        top.title("Edit Credential")
        top.geometry("300x200")
        fields = ["Username/Email", "Password", "Platform"]
        entries = []

        for i, field in enumerate(fields):
            ctk.CTkLabel(top, text=field).pack()
            e = ctk.CTkEntry(top)
            e.insert(0, record[i+1])
            e.pack()
            entries.append(e)

        def save_edit():
            new_username, new_password, new_platform = [e.get() for e in entries]
            edit_credential(record_id, new_username, new_password, new_platform)
            messagebox.showinfo(title="Success", message="Record updated")
            top.destroy()

        ctk.CTkButton(top, text="Save", command=save_edit).pack(pady=10)

    # -------------------- Delete Credential --------------------
    def delete_credentials_gui(self):
        rows = get_all_credentials()
        if not rows:
            messagebox.showinfo(title="Info", message="No records to delete")
            return
        record_id = simpledialog.askinteger("Delete Record", "Enter record ID to delete:")
        if record_id is None:
            return
        record = next((r for r in rows if r[0] == record_id), None)
        if record is None:
            messagebox.showerror(title="Error", message="Record not found")
            return
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this record?"):
            delete_credential(record_id)
            messagebox.showinfo(title="Deleted", message="Record deleted")

    # -------------------- Generate Password --------------------
    def generate_password_gui(self):
        password = "".join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        messagebox.showinfo(title="Generated Password", message=password)


# -------------------- Run Program --------------------
if __name__ == "__main__":
    PasswordManagerGUI()

