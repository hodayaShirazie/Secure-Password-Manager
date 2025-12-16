# PassKeep 🔐

A simple, local password manager written in Python with a modern CustomTkinter GUI and strong cryptography for secure storage of credentials.

PassKeep stores encrypted account credentials in a local SQLite database (`passwords.db`) and protects the master password using bcrypt hashing. AES is used to encrypt individual password entries before they are saved to disk.

## Key features
- AES encryption for stored passwords
- Master password hashing using bcrypt
- Local SQLite database (no cloud syncing by default)
- Graphical user interface built with CustomTkinter
- Single-file executable entrypoint: `passkeep.py`

## Requirements
- Python 3.10 or newer
- See `requirements.txt` for required Python packages (CustomTkinter, bcrypt, cryptography, etc.)

## Project layout
- `passkeep.py` — main application
- `passwords.db` — local SQLite database created/used by the app
- `requirements.txt` — Python dependencies
- `screenshots/` — UI screenshots
- `README.md` — this file

## Installation (Windows — PowerShell)
Open PowerShell and run the following commands in the project folder:

1) Create and activate a virtual environment

```powershell
python -m venv .venv
# PowerShell (may require Execution Policy change):
.\.venv\Scripts\Activate.ps1
# If the above fails, try the cross-shell activate script:
. .venv\Scripts\activate
```

2) Install dependencies

```powershell
pip install -r requirements.txt
```

## Running the app
With the virtual environment activated, start the application:

```powershell
python passkeep.py
```

The application will open a GUI window where you can create a master password (on first run), add new entries, view, update, and delete stored credentials.

## Usage notes
- On first run you will be asked to set a master password. Remember this password — it cannot be recovered by the app.
- The master password is hashed with bcrypt. Individual stored passwords are encrypted with AES and saved to `passwords.db`.
- Back up `passwords.db` if you need to transfer your passwords. Keep the database file and your master password private and secure.

## Security considerations
- PassKeep is designed as a local password manager. It does not transmit your passwords over the network.
- Do not reuse your master password elsewhere.
- Review and audit cryptographic code before using PassKeep to store high-value secrets.

## Contributing
Contributions and bug reports are welcome. Create an issue describing the problem or submit a pull request with your proposed changes.

## License
Specify your project license here (e.g., MIT). If you want a default, add a `LICENSE` file and state the license used.


---

If you want the README tailored further (screenshots embedded, example screenshots from `screenshots/`, or platform-specific packaging instructions), tell me which additions you want and I will update it.
