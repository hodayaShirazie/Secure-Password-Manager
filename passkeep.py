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
        self.root.title("Secure Password Manager")
        self.db_path = "passwords.db"

        width = 1200
        height = 500

        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = (screen_w // 2) - (width // 2)
        y = (screen_h // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.init_database()

        self.cursor.execute("SELECT key_hash FROM db_meta WHERE id=1")
        if self.cursor.fetchone() is None:
            self.show_registration_screen()
        else:
            self.show_login_screen()

        self.root.mainloop()

    # ------------------ KDF ------------------
    def derive_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            200_000,
            dklen=32
        )

    # ------------------ Database ------------------
    def init_database(self):
        new_db = not os.path.exists(self.db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        if new_db:
            self.cursor.execute("""
                CREATE TABLE db_meta (
                    id INTEGER PRIMARY KEY,
                    key_hash TEXT NOT NULL,
                    salt BLOB NOT NULL
                )""")
            self.cursor.execute("""
                CREATE TABLE credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    password TEXT,
                    platform TEXT
                )""")
            self.conn.commit()

    def get_db_meta(self):
        self.cursor.execute("SELECT key_hash, salt FROM db_meta WHERE id=1")
        return self.cursor.fetchone()

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
                    aes = AES.new(self.decryption_key, AES.MODE_CBC, self.decryption_key[:16])
                    dec_pwd = unpad(aes.decrypt(enc_pwd), AES.block_size).decode()
                except Exception:
                    dec_pwd = "<Error>"
            self.records.append([rid, user, dec_pwd, platform])
        self.records_count = len(self.records)

    def save_record(self, record):
        aes = AES.new(self.decryption_key, AES.MODE_CBC, self.decryption_key[:16])
        enc_pwd = aes.encrypt(pad(record[2].encode(), AES.block_size))
        enc_pwd_b64 = base64.b64encode(enc_pwd).decode()

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
    def center_popup(self, win):
        win.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        win_w = win.winfo_width()
        win_h = win.winfo_height()
        x = root_x + (root_w // 2) - (win_w // 2)
        y = root_y + (root_h // 2) - (win_h // 2)
        win.geometry(f"+{x}+{y}")

    def show_message(self, title, message):
        top = ctk.CTkToplevel(self.root)
        top.title(title)
        top.geometry("350x150")
        top.transient(self.root)
        top.grab_set()
        self.center_popup(top)
        ctk.CTkLabel(top, text=message, wraplength=300).pack(pady=20)
        ctk.CTkButton(top, text="OK", command=top.destroy).pack(pady=10)
        top.bind("<Return>", lambda e: top.destroy())

    # ------------------ Registration ------------------
    def show_registration_screen(self):
        self.reg_frame = ctk.CTkFrame(self.root)
        self.reg_frame.pack(pady=50, padx=50, fill="both", expand=True)

        ctk.CTkLabel(self.reg_frame, text="Create New Key:", font=("Arial", 16)).pack(pady=10)
        self.new_key_entry = ctk.CTkEntry(self.reg_frame, show="*")
        self.new_key_entry.pack(pady=10)
        self.new_key_entry.focus()

        ctk.CTkLabel(self.reg_frame, text="Confirm Key:", font=("Arial", 16)).pack(pady=10)
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

            salt = os.urandom(16)
            derived_key = self.derive_key(key, salt)
            key_hash = hashlib.sha256(derived_key).hexdigest()

            self.cursor.execute(
                "INSERT INTO db_meta (key_hash, salt) VALUES (?, ?)",
                (key_hash, salt)
            )
            self.conn.commit()

            self.decryption_key = derived_key
            self.db_key_hash = key_hash

            self.decrypt_passwords()  
            self.reg_frame.destroy()
            self.show_main_screen()

        ctk.CTkButton(self.reg_frame, text="Register", command=register).pack(pady=20)
        for entry in [self.new_key_entry, self.confirm_key_entry]:
            entry.bind("<Return>", lambda e: register())

    # ------------------ Login ------------------
    def show_login_screen(self):
        self.login_frame = ctk.CTkFrame(self.root)
        self.login_frame.pack(pady=50, padx=50, fill="both", expand=True)

        ctk.CTkLabel(self.login_frame, text="Enter Key:", font=("Arial", 16)).pack(pady=10)
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

        stored_hash, salt = self.get_db_meta()
        derived_key = self.derive_key(key, salt)
        key_hash = hashlib.sha256(derived_key).hexdigest()

        if key_hash != stored_hash:
            self.show_message("Error", "Incorrect key")
            return

        self.decryption_key = derived_key
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
            ctk.CTkButton(btn_frame, text=text, command=cmd, width=120).grid(row=0, column=i, padx=5)

        self.refresh_treeview()

    def refresh_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for record in self.records:
            self.tree.insert("", "end", values=record)


    # ------------------ Add/Edit/Delete ------------------
    def add_record_gui(self):
        """Opens a popup window for adding a new credential record."""

        self.record_popup("Add Credential")

    def edit_record_gui(self):
        """Opens a popup window for editing the selected credential record."""

        selected = self.tree.selection()
        if not selected:
            self.show_message("Info", "Select a record to edit")
            return
        rid = self.tree.item(selected[0])["values"][0]
        record = next(r for r in self.records if r[0] == rid)
        self.record_popup("Edit Credential", record)

    def record_popup(self, title, record=None):
        """Displays a popup window for adding or editing a credential record."""

        top = ctk.CTkToplevel(self.root)
        top.title(title)
        top.geometry("400x300")
        top.transient(self.root)
        top.grab_set()
        self.center_popup(top)

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
        """Displays a confirmation popup for deleting the selected credential record."""

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
        self.center_popup(top)
        ctk.CTkLabel(top, text="Are you sure you want to delete this record?", wraplength=300).pack(pady=20)

        def yes():
            self.delete_record(rid)
            top.destroy()

        ctk.CTkButton(top, text="Yes", command=yes).pack(side="left", padx=20, pady=10)
        ctk.CTkButton(top, text="No", command=top.destroy).pack(side="right", padx=20, pady=10)
        top.bind("<Return>", lambda e: yes())

    # ------------------ Other Utilities ------------------
    def change_db_password_gui(self):
        """Displays a popup for changing the database encryption key."""

        top = ctk.CTkToplevel(self.root)
        top.title("Change DB Password")
        top.geometry("400x300")
        top.transient(self.root)
        top.grab_set()
        self.center_popup(top)

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

            # --- אימות סיסמה ישנה באמצעות KDF ---
            self.cursor.execute("SELECT salt FROM db_meta WHERE id=1")
            salt = self.cursor.fetchone()[0]
            derived_current = self.derive_key(current, salt)
            if hashlib.sha256(derived_current).hexdigest() != self.db_key_hash:
                self.show_message("Error", "Incorrect current key")
                return

            if len(new) < 10:
                self.show_message("Error", "New key too short")
                return
            if new != confirm:
                self.show_message("Error", "Passwords do not match")
                return

            # --- פענוח כל הסיסמאות עם המפתח הישן ---
            decrypted_records = []
            old_key = derived_current
            for rec in self.records:
                if rec[2]:
                    aes_old = AES.new(old_key, AES.MODE_CBC, old_key[:16])
                    enc_pwd = base64.b64decode(self.cursor.execute(
                        "SELECT password FROM credentials WHERE id=?", (rec[0],)
                    ).fetchone()[0])
                    dec_pwd = unpad(aes_old.decrypt(enc_pwd), AES.block_size).decode()
                else:
                    dec_pwd = ""
                decrypted_records.append([rec[0], rec[1], dec_pwd, rec[3]])

            # --- יצירת מפתח חדש עם KDF + salt חדש ---
            new_salt = os.urandom(16)
            new_derived_key = self.derive_key(new, new_salt)
            self.decryption_key = new_derived_key
            self.db_key_hash = hashlib.sha256(new_derived_key).hexdigest()
            self.cursor.execute(
                "UPDATE db_meta SET key_hash=?, salt=? WHERE id=1",
                (self.db_key_hash, new_salt)
            )
            self.conn.commit()

            # --- הצפנה מחדש של כל הרשומות עם המפתח החדש ---
            for rec in decrypted_records:
                self.save_record(rec)

            self.show_message("Success", "Database password updated")
            top.destroy()

        ctk.CTkButton(top, text="Change Password", command=change).pack(pady=10)
        top.bind("<Return>", lambda e: change())

    def generate_password_gui(self):
        """Generates a secure random password and displays it to the user."""

        top = ctk.CTkToplevel(self.root)
        top.title("Generate Password")
        top.geometry("400x200")
        top.transient(self.root)
        top.grab_set()
        self.center_popup(top)

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
        """Creates a backup copy of the database file."""

        self.conn.close()
        backup_name = f"passwords_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copyfile(self.db_path, backup_name)
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.show_message("Backup", f"Backup created: {backup_name}")

    def erase_db_gui(self):
        """Displays a confirmation popup and erases all stored credentials."""

        top = ctk.CTkToplevel(self.root)
        top.title("Erase Database")
        top.geometry("350x150")
        top.transient(self.root)
        top.grab_set()
        self.center_popup(top)
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