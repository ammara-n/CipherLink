# CipherLink
### Team Members: 
Ammara Nizardeen, Fatma Zoghbar
## Project Description

CipherLink is a secure web-based communication platform developed to demonstrate the practical application of modern cryptographic techniques. The project focuses on protecting sensitive user data through encryption, secure file handling, and authenticated communication mechanisms.

The system is designed to provide:

* **Confidentiality** through encryption of sensitive information.
* **Integrity** by ensuring that transmitted and stored data cannot be altered without detection.
* **Authentication** to verify user identities and control access to resources.
* **Secure File Management** for handling user-uploaded files safely.
* **User-Friendly Interface** that allows users to interact with cryptographic functions without requiring advanced technical knowledge.

CipherLink was developed as part of a cryptography and cybersecurity project to showcase how modern security principles can be implemented in a real-world application. The project includes two versions, demonstrating the evolution of the system's features and security capabilities.

## Running the Project

This project contains two versions of CipherLink.

### Version 1 – CipherLink1

1. Download and extract the **CipherLink1** ZIP file.
2. Open the **CipherLink1** folder in Visual Studio Code.
3. Open a terminal in VS Code.
4. Run the following command:

```bash
python app.py
```

5. Open the local URL displayed in the terminal (typically `http://127.0.0.1:5000`).

---

### Version 2 – CipherLink2

1. Download and extract the **CipherLink2** ZIP file.
2. Open the extracted **CipherLink2** folder in Visual Studio Code.
3. Open a new terminal in VS Code.
4. Create a virtual environment:

```powershell
py -m venv .venv
```

5. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the activation script, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again.

6. Install the required packages:

```powershell
pip install -r requirements.txt
```

7. Run the application:

```powershell
python app_v2.py
```

8. Open the local URL displayed in the terminal, usually:

```text
http://127.0.0.1:5000
```

The SQLite database will be created automatically when the application starts.


## Requirements

* Python 3.x installed
* Visual Studio Code (recommended)

## Troubleshooting

If you encounter a missing module error, install the required dependencies using:

```bash
pip install -r requirements.txt
```
