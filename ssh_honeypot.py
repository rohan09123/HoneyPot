#!/usr/bin/env python3
"""
SSH Honeypot with Better Error Handling and Debugging
"""

import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
from datetime import datetime
import random
import os
import sys

# Constants
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Debian-3"
SERVER_KEY_FILE = 'server.key'

# Check and create server key if it doesn't exist
if not os.path.exists(SERVER_KEY_FILE):
    print(f"[!] Server key '{SERVER_KEY_FILE}' not found!")
    print("[*] Generating RSA key...")
    try:
        from paramiko import RSAKey
        key = RSAKey.generate(2048)
        key.write_private_key_file(SERVER_KEY_FILE)
        print(f"[+] Key generated and saved to '{SERVER_KEY_FILE}'")
    except Exception as e:
        print(f"[!] Error generating key: {e}")
        print("[!] Run this command manually:")
        print(f"    ssh-keygen -t rsa -f {SERVER_KEY_FILE} -N ''")
        sys.exit(1)

try:
    host_key = paramiko.RSAKey(filename=SERVER_KEY_FILE)
    print(f"[+] Loaded SSH key from '{SERVER_KEY_FILE}'")
except Exception as e:
    print(f"[!] Error loading key: {e}")
    sys.exit(1)

logging_format = logging.Formatter('%(asctime)s %(message)s')

# Loggers
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=50000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)
funnel_logger.propagate = False

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=50000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)
creds_logger.propagate = False

# Fake file system
FILE_SYSTEM = {
    '/home/corpuser': {
        'files': ['README.txt', '.bash_history', '.ssh/', 'documents/', 'scripts/'],
        'README.txt': 'Welcome to the corporate server. Please follow security policies.',
        '.bash_history': 'cd /var/www\nsudo systemctl restart apache2\ncat /etc/hosts\nexit',
    },
    '/home/corpuser/documents': {
        'files': ['passwords.txt', 'company_data.xlsx', 'meeting_notes.txt'],
        'passwords.txt': 'Nice try! Passwords are stored in the secure vault.',
    },
}

PROCESSES = [
    "1 root     systemd",
    "100 www-data apache2",
    "150 mysql    mysqld",
    "200 corpuser sshd",
]

def emulated_shell(channel, client_ip):
    """Emulated shell interface"""
    current_dir = '/home/corpuser'
    channel.send(b'corpuser@production-server:~$ ')
    command = b""
    
    try:
        while True:
            char = channel.recv(1)
            if not char:
                break
            
            channel.send(char)
            command += char
            
            if char == b'\r':
                cmd_str = command.strip().decode('utf-8', errors='ignore')
                
                if cmd_str:  # Only log non-empty commands
                    log_msg = f"{client_ip} executed: {cmd_str}"
                    creds_logger.info(log_msg)
                    creds_logger.handlers[0].flush()
                    print(f"[CMD] {client_ip}: {cmd_str}")
                
                response = process_command(cmd_str, current_dir, client_ip)
                
                if response == b'EXIT':
                    channel.send(b'\nGoodbye!\n')
                    break
                
                channel.send(response)
                prompt = f'corpuser@production-server:{current_dir}$ '.encode()
                channel.send(prompt)
                command = b""
                
    except Exception as e:
        print(f"[!] Shell error for {client_ip}: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def process_command(cmd, current_dir, client_ip):
    """Process shell commands"""
    cmd = cmd.strip()
    
    if not cmd:
        return b'\r\n'
    
    parts = cmd.split()
    
    # Basic commands
    if cmd == 'exit':
        return b'EXIT'
    elif cmd == 'pwd':
        return f'\n{current_dir}\r\n'.encode()
    elif cmd == 'whoami':
        return b'\ncorpuser\r\n'
    elif cmd == 'hostname':
        return b'\nproduction-server\r\n'
    elif cmd == 'id':
        return b'\nuid=1000(corpuser) gid=1000(corpuser) groups=1000(corpuser),27(sudo)\r\n'
    elif cmd.startswith('uname'):
        if '-a' in cmd:
            return b'\nLinux production-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n'
        return b'\nLinux\r\n'
    elif cmd.startswith('ls'):
        if current_dir in FILE_SYSTEM:
            files = FILE_SYSTEM[current_dir]['files']
            return ('\n' + '  '.join(files) + '\r\n').encode()
        return b'\nREADME.txt  documents/  scripts/\r\n'
    elif cmd.startswith('cat '):
        filename = cmd.split(' ', 1)[1] if len(parts) > 1 else ''
        if current_dir in FILE_SYSTEM and filename in FILE_SYSTEM[current_dir]:
            content = FILE_SYSTEM[current_dir][filename]
            return f'\n{content}\r\n'.encode()
        return f'\ncat: {filename}: No such file or directory\r\n'.encode()
    elif cmd.startswith('ps'):
        output = '\n  PID USER     COMMAND\r\n'
        for proc in PROCESSES:
            output += f'{proc}\r\n'
        return output.encode()
    elif cmd == 'history':
        return b'\n  1  ls -la\n  2  pwd\n  3  whoami\n  4  history\r\n'
    
    # Alert on suspicious commands
    elif cmd.startswith('sudo '):
        log_msg = f"[ALERT] {client_ip} attempted privilege escalation: {cmd}"
        print(log_msg)
        creds_logger.info(log_msg)
        return b'\n[sudo] password for corpuser: '
    elif cmd.startswith('wget ') or cmd.startswith('curl '):
        url = parts[1] if len(parts) > 1 else 'unknown'
        log_msg = f"[ALERT] {client_ip} attempted download: {url}"
        print(log_msg)
        creds_logger.info(log_msg)
        return f'\nConnecting to {url}... failed: Network unreachable\r\n'.encode()
    
    # Unknown command
    else:
        return f'\nbash: {parts[0]}: command not found\r\n'.encode()

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_auth_password(self, username, password):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"{timestamp} {self.client_ip} attempted login - Username: {username}, Password: {password}"
        funnel_logger.info(log_msg)
        funnel_logger.handlers[0].flush()
        print(f"[AUTH] {self.client_ip} - User: {username}, Pass: {password}")
        
        # If no specific credentials set, accept anything
        if self.input_username is None and self.input_password is None:
            print(f"[+] {self.client_ip} authenticated (accepting all credentials)")
            return paramiko.AUTH_SUCCESSFUL
        
        # Check specific credentials
        if username == self.input_username and password == self.input_password:
            print(f"[+] {self.client_ip} authenticated successfully")
            return paramiko.AUTH_SUCCESSFUL
        else:
            print(f"[-] {self.client_ip} authentication failed")
            return paramiko.AUTH_FAILED
            
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"\n[+] New connection from {client_ip}:{addr[1]}")
    
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        
        try:
            transport.start_server(server=server)
        except Exception as e:
            print(f"[!] Failed to start server for {client_ip}: {e}")
            return

        # Wait for auth
        channel = transport.accept(20)
        if channel is None:
            print(f"[-] {client_ip} - No channel opened (auth failed or timeout)")
            return

        print(f"[+] {client_ip} - Channel opened, sending banner")
        
        banner = f"Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
        banner += f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {client_ip}\n"
        channel.send(banner.encode())
        
        emulated_shell(channel, client_ip=client_ip)
        
    except Exception as error:
        print(f"[!] Error handling {client_ip}: {error}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            transport.close()
        except:
            pass
        try:
            client.close()
        except:
            pass
        print(f"[-] {client_ip} disconnected")

def honeypot(address, port, username, password):
    try:
        socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socks.bind((address, port))
        socks.listen(100)
        
        print("\n" + "="*60)
        print("SSH HONEYPOT STARTED")
        print("="*60)
        print(f"[*] Listening on: {address}:{port}")
        print(f"[*] Server: Ubuntu 22.04 LTS Production Server")
        
        if username and password:
            print(f"[*] Credentials: {username} / {password}")
        else:
            print(f"[*] Mode: Accept ANY credentials")
        
        print(f"[*] Logs: audits.log, cmd_audits.log")
        print(f"\n[*] Connect with: ssh -p {port} anyuser@{address}")
        print(f"[*] Press Ctrl+C to stop")
        print("="*60 + "\n")

        while True:
            try:
                client, addr = socks.accept()
                thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                print("\n\n[!] Shutting down honeypot...")
                break
            except Exception as error:
                print(f"[!] Error accepting connection: {error}")
                
    except Exception as e:
        print(f"[!] Failed to start honeypot: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            socks.close()
        except:
            pass

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Honeypot')
    parser.add_argument('-a', '--address', default='0.0.0.0', help='Bind address')
    parser.add_argument('-p', '--port', type=int, default=2223, help='Port number')
    parser.add_argument('-u', '--username', help='Required username (optional)')
    parser.add_argument('-pw', '--password', help='Required password (optional)')
    
    args = parser.parse_args()
    
    try:
        honeypot(args.address, args.port, args.username, args.password)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
