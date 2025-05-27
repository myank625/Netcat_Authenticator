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
- Admin privileges on Windows (for shell access and installation)  

---

## 🚀 Installation

Clone the repo:

```bash
git clone https://github.com/yourusername/netcat-authenticator.git
cd netcat-authenticator
