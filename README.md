## Version 2 – CipherLink2

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
