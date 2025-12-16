# PassKeep

PassKeep is a secure, local password manager for desktop users. It features a modern Python GUI and strong AES encryption to keep your credentials safe.

## Features
- AES encryption for all stored passwords
- Master password protection (hashed, never stored in plain text)
- Local SQLite database
- Modern, user-friendly interface
- Simple backup and restore

## Quick Start
- Python 3.10+
- Install dependencies: `pip install -r requirements.txt`
- Run: `python passkeep.py`

## Usage
- On first launch, set a master password (required for access)
- Add, edit, or delete credentials as needed
- All data is stored locally in `passwords.db`

## Project Structure
- `passkeep.py` - main application
- `passwords.db` - encrypted database
- `requirements.txt` - dependencies
- `test_passkeep.py` - unit tests
- `screenshots/` - UI images

