import socket
import paramiko
import threading
import sys
import os
import sqlite3
import requests
import time
import file_read
import fake_uname
import diskfile
import sudo_cmd

# =========================
# CONFIG
# =========================
DB_FILE = "honeypot_data.db"
LOG_FILE = "logs/honeypot.log"
API_IPINFO = "https://ipinfo.io/"

valid_credentials = {
    'admin': 'admin',
    'root': 'toor',
    'user': 'password123'
}

pwd = ["/var/www/html"]
os.makedirs("logs", exist_ok=True)

# =========================
# DATABASE INIT
# =========================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    location TEXT,
                    username TEXT,
                    password TEXT,
                    timestamp TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    command TEXT,
                    timestamp TEXT
                )''')
    conn.commit()
    conn.close()

def log_to_db(ip, location, username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO sessions (ip, location, username, password, timestamp) VALUES (?, ?, ?, ?, datetime('now'))",
              (ip, location, username, password))
    session_id = c.lastrowid
    conn.commit()
    conn.close()
    return session_id

def log_command(session_id, command):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO commands (session_id, command, timestamp) VALUES (?, ?, datetime('now'))",
              (session_id, command))
    conn.commit()
    conn.close()

# =========================
# GEOLOCATION
# =========================
def get_geo(ip):
    try:
        res = requests.get(API_IPINFO + ip, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')} ({data.get('org', '')})"
    except:
        pass
    return "Unknown"

# =========================
# LOGGING
# =========================
def log_event(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    print(msg)

# =========================
# SSH SERVER CLASS
# =========================
host_key = paramiko.RSAKey(filename='RSA_PRIVATE.key', password='FakeSSH')

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.session_id = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        location = get_geo(self.client_ip)
        self.session_id = log_to_db(self.client_ip, location, username, password)
        log_event(f"[LOGIN ATTEMPT] {self.client_ip} ({location}) - {username}:{password}")

        if username in valid_credentials and valid_credentials[username] == password:
            log_event(f"[AUTH SUCCESS] {username} logged in.")
            return paramiko.AUTH_SUCCESSFUL
        log_event(f"[AUTH FAIL] {username}/{password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# =========================
# COMMAND SIMULATION
# =========================
def get_pwd():
    return pwd[0]

def change_directory(cmd):
    spl = cmd.split(" ")
    if spl[1] == "..":
        if pwd[0] == "/var/www/html":
            return f"\r\n$ "
        else:
            spl_pwd = pwd[0].split("/")
            pwd_len = len(spl_pwd)
            c_pwd=""
            for i in range(1, pwd_len-1):
                c_pwd = c_pwd+"/"+spl_pwd[i]
                pwd[0] = c_pwd
            return f"\r\n$ "
    elif spl[1] == "":
        pwd[0] = "/var/www/html"
        return f"\r\n$ "
    else:
        dir_name = spl[1]
        alf = file_read.change_directory(dir_name)
        if isinstance(alf, dict):
            pwd[0]=pwd[0]+"/"+dir_name
            return f"\r\n$ "
        return f"\r\n{alf}\r\n$ "

def command_handler(cmd):
    if cmd == "pwd":
        return f"\r\n{get_pwd()} \r\n$ "
    elif cmd == "ls":
        pswd = get_pwd()
        files = file_read.Dir_Handler(pswd)
        return f"\r\n{files} \r\n$ "
    elif "cd " in cmd:
        return change_directory(cmd)
    elif cmd.startswith("uname"):
        return f"\r\n{fake_uname.uname_handle(cmd)} \r\n$ "
    elif cmd == "df -h":
        return f"\r\n{diskfile.disk_handler()} \r\n$ "
    elif cmd.startswith("free"):
        return f"\r\n{diskfile.memory_haneler()} \r\n$ "
    elif cmd.startswith("sudo apt") or "apt " in cmd:
        return f"\r\n{sudo_cmd.cmd_response()} \r\n$ "
    elif cmd == "whoami":
        return "\r\nroot\r\n$ "
    elif cmd == "id":
        return "\r\nuid=0(root) gid=0(root) groups=0(root)\r\n$ "
    elif cmd == "cat /etc/passwd":
        return "\r\nroot:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:,,,:/home/user:/bin/bash\r\n$ "
    else:
        return f"\r\nCommand '{cmd}' not found\r\n$ "

# =========================
# CLIENT HANDLER
# =========================
def handle_client(client_socket, client_ip):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = SSHHoneypot(client_ip)

    try:
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            log_event("[-] No channel request")
            return

        log_event(f"[+] Channel opened for {client_ip}")
        server.event.wait(10)

        if not server.event.is_set():
            log_event("[-] No shell request")
            return

        chan.send("Welcome to the SSH Honeypot!\r\n$ ")
        command_buffer = ""

        while True:
            try:
                data = chan.recv(1024).decode('utf-8')
                if not data:
                    break
                if data in ['\r', '\n']:
                    command = command_buffer.strip()
                    if command:
                        log_command(server.session_id, command)
                        log_event(f"[CMD] {client_ip}: {command}")
                        chan.send(command_handler(command))
                    command_buffer = ""
                else:
                    command_buffer += data
                    chan.send(data)
            except Exception as e:
                log_event(f"Error: {e}")
                break
    finally:
        transport.close()

# =========================
# MAIN
# =========================
def start_honeypot():
    init_db()
    host = input("Enter your IP: ")
    port = 22
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    log_event(f"[+] SSH Honeypot running on {host}:{port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            log_event(f"[+] Connection from {client_ip}")
            threading.Thread(target=handle_client, args=(client_socket, client_ip)).start()
    except KeyboardInterrupt:
        log_event("Exiting honeypot...")
        sys.exit()

if __name__ == "__main__":
    start_honeypot()
