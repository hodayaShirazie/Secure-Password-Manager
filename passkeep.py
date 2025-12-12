import hashlib, os, sys, random, string, shutil, sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import customtkinter as ctk
from tkinter import ttk
import base64
import datetime

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class PasswordManagerGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.geometry("800x500")
        self.root.title("Secure Password Manager")
        self.db_path = "passwords.db"

        self.init_database()

        # אם אין סיסמה ב-db → רישום חדש, אחרת → login
        self.cursor.execute("SELECT key_hash FROM db_meta WHERE id=1")
        if self.cursor.fetchone() is None:
            self.show_registration_screen()
        else:
            self.show_login_screen()

        self.root.mainloop()

    # ------------------ Database ------------------
    def init_database(self):
        new_db = not os.path.exists(self.db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        if new_db:
            self.cursor.execute("""
                CREATE TABLE db_meta (
                    id INTEGER PRIMARY KEY,
                    key_hash TEXT NOT NULL
                )""")
            self.cursor.execute("""
                CREATE TABLE credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    password TEXT,
                    platform TEXT
                )""")
            self.conn.commit()  # ללא סיסמה דיפולטית

    def pad_key(self, key):
        return key + ("0" * (16 - len(key) % 16)) if len(key) % 16 != 0 else key

    def get_db_hash(self):
        self.cursor.execute("SELECT key_hash FROM db_meta WHERE id=1")
        return self.cursor.fetchone()[0]

    def decrypt_passwords(self):
        self.cursor.execute("SELECT id, username, password, platform FROM credentials")
        self.records = []
        for row in self.cursor.fetchall():
            rid, user, enc_pwd_b64, platform = row
            dec_pwd = ""
            if enc_pwd_b64:
                try:
                    missing_padding = len(enc_pwd_b64) % 4
                    if missing_padding:
                        enc_pwd_b64 += '=' * (4 - missing_padding)
                    enc_pwd = base64.b64decode(enc_pwd_b64)
                    aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
                    dec_pwd = unpad(aes.decrypt(enc_pwd), AES.block_size).decode()
                except Exception as e:
                    print(f"Failed to decrypt record {rid}: {e}")
                    dec_pwd = "<Error>"
            self.records.append([rid, user, dec_pwd, platform])
        self.records_count = len(self.records)

    def save_record(self, record):
        aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
        enc_pwd = aes.encrypt(pad(record[2].encode(), AES.block_size))
        enc_pwd_b64 = base64.b64encode(enc_pwd).decode()  # שמירה כ-string

        if record[0] is None:
            self.cursor.execute(
                "INSERT INTO credentials (username, password, platform) VALUES (?, ?, ?)",
                (record[1], enc_pwd_b64, record[3])
            )
        else:
            self.cursor.execute(
                "UPDATE credentials SET username=?, password=?, platform=? WHERE id=?",
                (record[1], enc_pwd_b64, record[3], record[0])
            )
        self.conn.commit()
        self.decrypt_passwords()
        self.refresh_treeview()

    def delete_record(self, rid):
        self.cursor.execute("DELETE FROM credentials WHERE id=?", (rid,))
        self.conn.commit()
        self.decrypt_passwords()
        self.refresh_treeview()

    # ------------------ GUI Message ------------------
    def show_message(self, title, message):
        top = ctk.CTkToplevel(self.root)
        top.title(title)
        top.geometry("350x150")
        top.transient(self.root)
        top.grab_set()
        ctk.CTkLabel(top, text=message, wraplength=300).pack(pady=20)
        ctk.CTkButton(top, text="OK", command=top.destroy).pack(pady=10)
        top.bind("<Return>", lambda e: top.destroy())

    # ------------------ Registration Screen ------------------
    def show_registration_screen(self):
        self.reg_frame = ctk.CTkFrame(self.root)
        self.reg_frame.pack(pady=50, padx=50, fill="both", expand=True)

        ctk.CTkLabel(self.reg_frame, text="Create New Decryption Key:", font=("Arial", 16)).pack(pady=10)
        self.new_key_entry = ctk.CTkEntry(self.reg_frame, show="*")
        self.new_key_entry.pack(pady=10)
        self.new_key_entry.focus()

        ctk.CTkLabel(self.reg_frame, text="Confirm Decryption Key:", font=("Arial", 16)).pack(pady=10)
        self.confirm_key_entry = ctk.CTkEntry(self.reg_frame, show="*")
        self.confirm_key_entry.pack(pady=10)

        def register():
            key = self.new_key_entry.get()
            confirm = self.confirm_key_entry.get()
            if not key or not confirm:
                self.show_message("Error", "All fields are required")
                return
            if key != confirm:
                self.show_message("Error", "Keys do not match")
                return
            if len(key) < 10:
                self.show_message("Error", "Key too short")
                return

            padded_key = self.pad_key(key)
            key_hash = hashlib.sha256(padded_key.encode()).hexdigest()
            self.cursor.execute("INSERT INTO db_meta (key_hash) VALUES (?)", (key_hash,))
            self.conn.commit()

            self.decryption_key = padded_key
            self.db_key_hash = key_hash

            self.reg_frame.destroy()
            self.show_main_screen()

        ctk.CTkButton(self.reg_frame, text="Register", command=register).pack(pady=20)

    # ------------------ Login ------------------
    def show_login_screen(self):
        self.login_frame = ctk.CTkFrame(self.root)
        self.login_frame.pack(pady=50, padx=50, fill="both", expand=True)

        ctk.CTkLabel(self.login_frame, text="Enter Decryption Key:", font=("Arial", 16)).pack(pady=10)
        self.key_entry = ctk.CTkEntry(self.login_frame, show="*")
        self.key_entry.pack(pady=10)
        self.key_entry.focus()
        self.key_entry.bind("<Return>", lambda e: self.verify_login())

        ctk.CTkButton(self.login_frame, text="Login", command=self.verify_login).pack(pady=20)

    def verify_login(self):
        key = self.key_entry.get()
        if not key:
            self.show_message("Error", "Please enter a key")
            return
        self.decryption_key = self.pad_key(key)
        key_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
        if key_hash != self.get_db_hash():
            self.show_message("Error", "Incorrect key")
            return
        self.db_key_hash = key_hash
        self.login_frame.destroy()
        self.decrypt_passwords()
        self.show_main_screen()

    # ------------------ Main Screen ------------------
    def show_main_screen(self):
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("ID", "Username", "Password", "Platform")
        self.tree = ttk.Treeview(self.main_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)
        self.tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        btn_frame = ctk.CTkFrame(self.root)
        btn_frame.pack(fill="x", padx=10, pady=10)

        actions = [
            ("Add", self.add_record_gui),
            ("Edit", self.edit_record_gui),
            ("Delete", self.delete_record_gui),
            ("Change DB Password", self.change_db_password_gui),
            ("Generate Password", self.generate_password_gui),
            ("Backup DB", self.backup_db_gui),
            ("Erase DB", self.erase_db_gui),
            ("Exit", self.root.destroy)
        ]

        for i, (text, cmd) in enumerate(actions):
            b = ctk.CTkButton(btn_frame, text=text, command=cmd, width=120)
            b.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
        for i in range(len(actions)):
            btn_frame.grid_columnconfigure(i, weight=1)

        self.refresh_treeview()

    def refresh_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for record in self.records:
            self.tree.insert("", "end", values=record)

    # ------------------ Add/Edit/Delete ------------------
    def add_record_gui(self):
        self.record_popup("Add Credential")

    def edit_record_gui(self):
        selected = self.tree.selection()
        if not selected:
            self.show_message("Info", "Select a record to edit")
            return
        rid = self.tree.item(selected[0])["values"][0]
        record = next(r for r in self.records if r[0] == rid)
        self.record_popup("Edit Credential", record)

    def record_popup(self, title, record=None):
        top = ctk.CTkToplevel(self.root)
        top.title(title)
        top.geometry("400x300")
        top.transient(self.root)
        top.grab_set()

        labels = ["Username/Email", "Password", "Platform"]
        entries = []

        for i, label in enumerate(labels):
            ctk.CTkLabel(top, text=label).pack(pady=5)
            if record and label == "Password":
                e = ctk.CTkEntry(top)
            else:
                e = ctk.CTkEntry(top, show="*" if "Password" in label else "")
            if record:
                e.insert(0, record[i+1])
            e.pack(pady=5)
            entries.append(e)

        def save():
            username, password, platform = [e.get() for e in entries]
            if not username or not password or not platform:
                self.show_message("Error", "All fields are required")
                return
            if record:
                record[1], record[2], record[3] = username, password, platform
                self.save_record(record)
            else:
                self.save_record([None, username, password, platform])
            top.destroy()

        save_button = ctk.CTkButton(top, text="Save", command=save)
        save_button.pack(pady=10)
        top.bind("<Return>", lambda e: save())

    def delete_record_gui(self):
        selected = self.tree.selection()
        if not selected:
            self.show_message("Info", "Select a record to delete")
            return
        rid = self.tree.item(selected[0])["values"][0]
        top = ctk.CTkToplevel(self.root)
        top.title("Confirm Delete")
        top.geometry("350x150")
        top.transient(self.root)
        top.grab_set()
        ctk.CTkLabel(top, text="Are you sure you want to delete this record?", wraplength=300).pack(pady=20)

        def yes():
            self.delete_record(rid)
            top.destroy()

        ctk.CTkButton(top, text="Yes", command=yes).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(top, text="No", command=top.destroy).pack(side="right", padx=20, pady=10)
        top.bind("<Return>", lambda e: yes())

    # ------------------ Other Utilities ------------------
    def change_db_password_gui(self):
        top = ctk.CTkToplevel(self.root)
        top.title("Change DB Password")
        top.geometry("400x300")
        top.transient(self.root)
        top.grab_set()

        entries = []
        for label, show in [("Current Key", "*"), ("New Key", "*"), ("Confirm New Key", "*")]:
            ctk.CTkLabel(top, text=label).pack(pady=5)
            e = ctk.CTkEntry(top, show=show)
            e.pack(pady=5)
            entries.append(e)

        def change():
            current, new, confirm = [e.get() for e in entries]
            if not current or not new or not confirm:
                self.show_message("Error", "All fields are required")
                return

            old_key = self.decryption_key
            if hashlib.sha256(self.pad_key(current).encode()).hexdigest() != self.db_key_hash:
                self.show_message("Error", "Incorrect current key")
                return
            if len(new) < 10:
                self.show_message("Error", "New key too short")
                return
            if new != confirm:
                self.show_message("Error", "Passwords do not match")
                return

            decrypted_records = []
            for rec in self.records:
                if rec[2]:
                    aes_old = AES.new(old_key.encode(), AES.MODE_CBC, old_key[:16].encode())
                    enc_pwd = base64.b64decode(self.cursor.execute(
                        "SELECT password FROM credentials WHERE id=?", (rec[0],)
                    ).fetchone()[0])
                    dec_pwd = unpad(aes_old.decrypt(enc_pwd), AES.block_size).decode()
                else:
                    dec_pwd = ""
                decrypted_records.append([rec[0], rec[1], dec_pwd, rec[3]])

            self.decryption_key = self.pad_key(new)
            self.db_key_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
            self.cursor.execute("UPDATE db_meta SET key_hash=? WHERE id=1", (self.db_key_hash,))
            self.conn.commit()

            for rec in decrypted_records:
                self.save_record(rec)

            self.show_message("Success", "Database password updated")
            top.destroy()

        ctk.CTkButton(top, text="Change Password", command=change).pack(pady=10)
        top.bind("<Return>", lambda e: change())

    def generate_password_gui(self):
        top = ctk.CTkToplevel(self.root)
        top.title("Generate Password")
        top.geometry("400x200")
        top.transient(self.root)
        top.grab_set()

        pwd = "".join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=32))
        ctk.CTkLabel(top, text="Generated Password:").pack(pady=10)
        pwd_entry = ctk.CTkEntry(top)
        pwd_entry.pack(pady=5, padx=10, fill="x")
        pwd_entry.insert(0, pwd)

        def copy_pwd():
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd_entry.get())
            self.show_message("Copied", "Password copied to clipboard!")
            top.destroy()

        ctk.CTkButton(top, text="Copy", command=copy_pwd).pack(pady=10)
        top.bind("<Return>", lambda e: copy_pwd())

    def backup_db_gui(self):
        self.conn.close()
        backup_name = f"passwords_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copyfile(self.db_path, backup_name)
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.show_message("Backup", f"Backup created: {backup_name}")

    def erase_db_gui(self):
        top = ctk.CTkToplevel(self.root)
        top.title("Erase Database")
        top.geometry("350x150")
        top.transient(self.root)
        top.grab_set()
        ctk.CTkLabel(top, text="Are you sure you want to erase the database?", wraplength=300).pack(pady=20)

        def yes():
            self.cursor.execute("DELETE FROM credentials")
            self.conn.commit()
            self.decrypt_passwords()
            self.refresh_treeview()
            top.destroy()
            self.show_message("Erased", "Database erased")

        ctk.CTkButton(top, text="Yes", command=yes).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(top, text="No", command=top.destroy).pack(side="right", padx=20, pady=10)
        top.bind("<Return>", lambda e: yes())


if __name__ == "__main__":
    PasswordManagerGUI()
