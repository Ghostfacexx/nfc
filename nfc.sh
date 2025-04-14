cat << 'EOF' > nfc.sh
#!/bin/bash

# Step 1: Update and upgrade system packages
echo "Updating and upgrading system..."
sudo apt update && sudo apt upgrade -y

# Step 2: Install required system packages
echo "Installing system packages..."
sudo apt install -y python3.12 git python3-pip python3-dev python3-venv software-properties-common build-essential wget python3.12-venv protobuf-compiler

# Step 3: Create virtual environment at /root/nfcrelay-venv
echo "Creating virtual environment..."
python3 -m venv /root/nfcrelay-venv

# Step 4: Activate virtual environment
echo "Activating virtual environment..."
source /root/nfcrelay-venv/bin/activate

# Step 5: Install Python packages in the virtual environment
echo "Installing Python packages..."
pip install --upgrade pip
pip install psutil requests protobuf==3.20.0

# Step 6: Navigate to /root
cd /root

# Step 7: Clone the repository with submodules
echo "Cloning repository..."
if [ ! -d "server1" ]; then
    git clone --recurse-submodules https://github.com/nfcgate/server.git server1
else
    echo "server1 directory already exists, skipping clone"
fi

# Step 8: Navigate to server1
cd server1

# Step 9: Verify .proto files in protocol/protobuf
echo "Checking for .proto files..."
if [ -z "$(ls protocol/protobuf/*.proto 2>/dev/null)" ]; then
    echo "Error: No .proto files found in /root/server1/protocol/protobuf. Exiting."
    exit 1
fi

# Step 10: Compile protocol buffer files
echo "Compiling .proto files..."
protoc --python_out=plugins protocol/protobuf/*.proto || { echo "protoc failed, check .proto files"; exit 1; }

# Step 11: Ensure logs directory exists
echo "Ensuring log directory exists..."
mkdir -p /root/server/logs
mkdir -p logs  # For server.py logs in /root/server1/logs

# Step 12: Create server1.py with the specified code
echo "Creating server1.py..."
cat << 'INNER_EOF' > /root/server1/server1.py
#!/usr/bin/env python3
import argparse
import socket
import socketserver
import ssl
import struct
import datetime
import sys
import logging
import os
import threading
import time
import psutil
import traceback
import ipaddress
import requests
from logging.handlers import RotatingFileHandler
from binascii import hexlify
from plugins.c2s_pb2 import ServerData
from plugins.c2c_pb2 import NFCData

HOST = "0.0.0.0"
PORT = 5566
LOG_DIR = "/root/server/logs"
LOG_FILE = os.path.join(LOG_DIR, "nfcgate_server.log")
NOTIFY_URL = "http://localhost"  # Replaced placeholder webhook URL

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger = logging.getLogger('NFCGateServer')
logger.setLevel(logging.DEBUG)

class MicrosecondFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = datetime.datetime.fromtimestamp(record.created)
        return ct.strftime('%Y-%m-%d %H:%M:%S.%f')

formatter = MicrosecondFormatter(
    '%(asctime)s [%(levelname)s] [%(name)s] [PID:%(process)d] [Thread:%(thread)d] '
    '[Client:%(client_addr)s] [Session:%(session_id)s] [Seq:%(seq_num)s] %(message)s'
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=10*1024*1024, backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

packet_seq = 0
seq_lock = threading.Lock()

def log_with_context(message, level=logging.INFO, client=None, session=None, extra_data=None):
    global packet_seq
    with seq_lock:
        packet_seq += 1
        seq_num = packet_seq
    extra = {
        'client_addr': client.client_address if client else 'N/A',
        'session_id': str(session) if session is not None else 'None',
        'seq_num': seq_num
    }
    if extra_data:
        extra.update(extra_data)
    logger.log(level, message, extra=extra)

def notify_online(ip):
    try:
        data = {"server": "NFCGate", "ip": ip, "status": "online", "timestamp": int(time.time())}
        requests.post(NOTIFY_URL, json=data, timeout=5)
        log_with_context(f"Notification sent: IP={ip}", logging.DEBUG)
    except Exception as e:
        log_with_context(f"Notification failed: {str(e)}", logging.WARNING)

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def parse_protobuf(data):
    try:
        server_msg = ServerData()
        server_msg.ParseFromString(data)
        opcode = ServerData.Opcode.Name(server_msg.opcode)
        inner_data = hexlify(server_msg.data).decode()
        try:
            nfc_data = NFCData()
            nfc_data.ParseFromString(server_msg.data)
            source = NFCData.DataSource.Name(nfc_data.data_source)
            dtype = NFCData.DataType.Name(nfc_data.data_type)
            ts = nfc_data.timestamp
            nfc_bytes = hexlify(nfc_data.data).decode()
            return (f"ServerData(opcode={opcode}, data=NFCData(source={source}, "
                    f"type={dtype}, timestamp={ts}, data={nfc_bytes}))")
        except Exception:
            return f"ServerData(opcode={opcode}, data={inner_data})"
    except Exception:
        try:
            nfc_data = NFCData()
            nfc_data.ParseFromString(data)
            source = NFCData.DataSource.Name(nfc_data.data_source)
            dtype = NFCData.DataType.Name(nfc_data.data_type)
            ts = nfc_data.timestamp
            nfc_bytes = hexlify(nfc_data.data).decode()
            return f"NFCData(source={source}, type={dtype}, timestamp={ts}, data={nfc_bytes})"
        except Exception:
            return f"Unparseable data: {hexlify(data).decode()}"

def resolve_ip(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return f"{ip} ({hostname})"
    except socket.herror:
        return ip

class PluginHandler:
    def __init__(self, plugins):
        self.plugin_list = []
        for modname in plugins:
            try:
                plugin = __import__("plugins.mod_%s" % modname, fromlist=["plugins"])
                self.plugin_list.append((modname, plugin))
                log_with_context(f"Loaded plugin: mod_{modname} | Module path: {plugin.__file__}", logging.INFO)
            except ImportError as e:
                log_with_context(f"Failed to load plugin mod_{modname}: {str(e)}", logging.ERROR)

    def filter(self, client, data):
        log_with_context(f"Filtering data: {hexlify(data).decode()} | Parsed: {parse_protobuf(data)}", 
                        logging.DEBUG, client=client, session=client.session)
        for modname, plugin in self.plugin_list:
            try:
                if type(data) == list:
                    first = data[0]
                else:
                    first = data
                plugin_log = []
                def plugin_logger(*args):
                    msg = " ".join(str(arg) for arg in args)
                    plugin_log.append(msg)
                    log_with_context(msg, logging.INFO, client=client, session=client.session, extra_data={'tag': modname})
                first = plugin.handle_data(plugin_logger, first, client.state)
                if plugin_log:
                    log_with_context(f"Plugin {modname} logged: {plugin_log}", logging.DEBUG, client=client, session=client.session)
                if type(data) == list:
                    data = [first] + data[1:]
                else:
                    data = first
                log_with_context(f"Plugin {modname} processed data: {hexlify(data if type(data) != list else data[0]).decode()} | Parsed: {parse_protobuf(data)}", 
                                logging.DEBUG, client=client, session=client.session)
            except Exception as e:
                log_with_context(f"Plugin {modname} failed: {str(e)} | Stack: {traceback.format_exc()}", 
                                logging.ERROR, client=client, session=client.session)
        return data

class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, srv):
        self.session = None
        self.state = {}
        self.last_packet_time = time.time()
        self.connect_time = time.time()
        super().__init__(request, client_address, srv)

    def setup(self):
        super().setup()
        self.request.settimeout(300)
        ip_info = resolve_ip(self.client_address[0])
        log_with_context(f"Client connected | Socket: {self.request.getsockname()} -> {self.request.getpeername()} | "
                        f"IP: {ip_info} | Timeout: {self.request.gettimeout()}s | Thread: {threading.current_thread().name}", 
                        logging.INFO, client=self)
        log_with_context(f"System stats: CPU={psutil.cpu_percent()}%, Memory={psutil.virtual_memory().percent}% | "
                        f"Thread stack: {traceback.format_stack()[-5:-1]}", logging.DEBUG, client=self)

    def handle(self):
        super().handle()
        log_with_context("Starting client handler loop", logging.DEBUG, client=self)
        while True:
            try:
                start_time = time.time()
                msg_len_data = self.rfile.read(5)
                read_time = time.time()
                log_with_context(f"Read message length data: {hexlify(msg_len_data).decode()} | "
                                f"Bytes read: {len(msg_len_data)} | Time taken: {(read_time - start_time)*1000:.3f}ms", 
                                logging.DEBUG, client=self, session=self.session)
            except socket.timeout:
                log_with_context(f"Client timed out after 300s | Idle time: {(time.time() - self.last_packet_time):.2f}s", 
                                logging.WARNING, client=self, session=self.session)
                break
            except Exception as e:
                log_with_context(f"Error reading message length: {str(e)} | Stack: {traceback.format_exc()}", 
                                logging.ERROR, client=self, session=self.session)
                break

            if len(msg_len_data) < 5:
                log_with_context(f"Received incomplete length data ({len(msg_len_data)} bytes), disconnecting | "
                                f"Buffer state: {hexlify(msg_len_data).decode()}", 
                                logging.WARNING, client=self, session=self.session)
                break

            try:
                msg_len, session = struct.unpack("!IB", msg_len_data)
                log_with_context(f"Parsed message: length={msg_len}, session={session}", logging.DEBUG, client=self, session=self.session)
            except struct.error as e:
                log_with_context(f"Failed to unpack message length: {str(e)} | Raw: {hexlify(msg_len_data).decode()}", 
                                logging.ERROR, client=self, session=self.session)
                break

            data = self.rfile.read(msg_len)
            self.last_packet_time = time.time()
            log_with_context(f"Received data: {hexlify(data).decode()} | Parsed: {parse_protobuf(data)} | "
                            f"Time since last packet: {(self.last_packet_time - start_time)*1000:.3f}ms | "
                            f"Client uptime: {(self.last_packet_time - self.connect_time):.2f}s", 
                            logging.INFO, client=self, session=self.session)

            if msg_len == 0 or (session == 0 and self.session is None):
                log_with_context("Empty message or no session, disconnecting", logging.WARNING, client=self, session=self.session)
                break

            if self.session != session:
                log_with_context(f"Session change detected: old={self.session}, new={session}", logging.INFO, client=self)
                self.server.remove_client(self, self.session)
                self.session = session
                self.server.add_client(self, session)

            try:
                filtered_data = self.server.plugins.filter(self, data)
                self.server.send_to_clients(self.session, filtered_data, self)
            except Exception as e:
                log_with_context(f"Error processing or sending data: {str(e)} | Stack: {traceback.format_exc()}", 
                                logging.ERROR, client=self, session=self.session)

    def finish(self):
        log_with_context(f"Client disconnecting | Uptime: {(time.time() - self.connect_time):.2f}s", 
                        logging.INFO, client=self, session=self.session)
        self.server.remove_client(self, self.session)
        super().finish()

class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, request_handler, plugins, tls_options=None, bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, request_handler, bind_and_activate)
        self.clients = {}
        self.plugins = PluginHandler(plugins)
        self.tls_options = tls_options
        self.start_time = time.time()

        log_with_context(f"NFCGate server initialized on {server_address} | Active threads: {threading.active_count()}", 
                        logging.INFO)
        if self.tls_options:
            log_with_context(f"TLS enabled: cert={self.tls_options['cert_file']}, key={self.tls_options['key_file']}", 
                            logging.INFO)
        host_ip = get_host_ip()
        threading.Thread(target=notify_online, args=(host_ip,), daemon=True).start()

    def get_request(self):
        client_socket, from_addr = super().get_request()
        ip_info = resolve_ip(from_addr[0])
        log_with_context(f"New connection from {from_addr} | Socket: {client_socket.getsockname()} | "
                        f"IP: {ip_info} | Server uptime: {(time.time() - self.start_time):.2f}s", 
                        logging.DEBUG)
        if not self.tls_options:
            return client_socket, from_addr
        try:
            wrapped_socket = self.tls_options["context"].wrap_socket(client_socket, server_side=True)
            log_with_context(f"TLS handshake completed for {from_addr} | Cipher: {wrapped_socket.cipher()} | "
                            f"SSL version: {wrapped_socket.version()}", logging.DEBUG)
            return wrapped_socket, from_addr
        except ssl.SSLError as e:
            log_with_context(f"TLS handshake failed: {str(e)} | Stack: {traceback.format_exc()}", logging.ERROR)
            raise

    def add_client(self, client, session):
        if session is None:
            log_with_context("Attempted to add client to null session", logging.WARNING, client=client)
            return

        if session not in self.clients:
            self.clients[session] = []
            log_with_context(f"Created new session {session}", logging.INFO, client=client)

        self.clients[session].append(client)
        log_with_context(f"Client joined session {session}, total clients={len(self.clients[session])} | "
                        f"Session clients: {[c.client_address for c in self.clients[session]]}", 
                        logging.INFO, client=client, session=session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            log_with_context("Attempted to remove client from null or unknown session", logging.WARNING, client=client, session=session)
            return

        self.clients[session].remove(client)
        log_with_context(f"Client left session {session}, remaining clients={len(self.clients[session])} | "
                        f"Remaining: {[c.client_address for c in self.clients[session]]}", 
                        logging.INFO, client=client, session=session)
        if not self.clients[session]:
            del self.clients[session]
            log_with_context(f"Session {session} emptied and removed", logging.INFO, client=client)

    def send_to_clients(self, session, msgs, origin):
        if session is None or session not in self.clients:
            log_with_context(f"Cannot send to null or unknown session {session}", logging.WARNING, client=origin, session=session)
            return

        if type(msgs) != list:
            msgs = [msgs]

        for client in self.clients[session]:
            if client is origin:
                continue
            try:
                for msg in msgs:
                    msg_len = len(msg)
                    start_time = time.time()
                    client.wfile.write(int.to_bytes(msg_len, 4, byteorder='big'))
                    client.wfile.write(msg)
                    send_time = (time.time() - start_time) * 1000
                    log_with_context(f"Sent {msg_len} bytes to client: {hexlify(msg).decode()} | Parsed: {parse_protobuf(msg)} | "
                                    f"Send time: {send_time:.3f}ms", 
                                    logging.DEBUG, client=client, session=session)
            except Exception as e:
                log_with_context(f"Failed to send to client: {str(e)} | Stack: {traceback.format_exc()}", 
                                logging.ERROR, client=client, session=session)

        log_with_context(f"Published to {len(self.clients[session]) - 1} clients in session {session} | "
                        f"Recipients: {[c.client_address for c in self.clients[session] if c is not origin]}", 
                        logging.INFO, client=origin, session=session)

def parse_args():
    parser = argparse.ArgumentParser(prog="NFCGate server")
    parser.add_argument("plugins", type=str, nargs="*", help="List of plugin modules to load.", default=["log"])
    parser.add_argument("-s", "--tls", help="Enable TLS. You must specify certificate and key.",
                        default=False, action="store_true")
    parser.add_argument("--tls_cert", help="TLS certificate file in PEM format.", action="store")
    parser.add_argument("--tls_key", help="TLS key file in PEM format.", action="store")

    args = parser.parse_args()
    tls_options = None

    if args.tls:
        if args.tls_cert is None or args.tls_key is None:
            log_with_context("TLS enabled but cert or key missing", logging.CRITICAL)
            sys.exit(1)

        tls_options = {
            "cert_file": args.tls_cert,
            "key_file": args.tls_key
        }
        try:
            tls_options["context"] = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            tls_options["context"].load_cert_chain(tls_options["cert_file"], tls_options["key_file"])
            log_with_context("TLS context loaded successfully", logging.INFO)
        except ssl.SSLError as e:
            log_with_context(f"TLS cert/key load failed: {str(e)} | Stack: {traceback.format_exc()}", logging.CRITICAL)
            sys.exit(1)

    return args.plugins, tls_options

def main():
    plugins, tls_options = parse_args()
    log_with_context(f"Starting server with plugins: {plugins} | System: CPU={psutil.cpu_percent()}%, "
                    f"Memory={psutil.virtual_memory().percent}% | Stack: {traceback.format_stack()[-3:-1]}", logging.INFO)
    server = NFCGateServer((HOST, PORT), NFCGateClientHandler, plugins, tls_options)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_with_context(f"Server interrupted by user, shutting down | Uptime: {(time.time() - server.start_time):.2f}s", 
                        logging.INFO)
        server.shutdown()
    except Exception as e:
        log_with_context(f"Server crashed: {str(e)} | Stack: {traceback.format_exc()}", logging.CRITICAL)

if __name__ == "__main__":
    main()
INNER_EOF

# Step 13: Make server1.py executable
echo "Making server1.py executable..."
chmod +x /root/server1/server1.py

# Step 14: Verify server1.py creation
echo "Verifying server1.py creation..."
ls -l /root/server1/server1.py || { echo "Failed to create server1.py"; exit 1; }

# Step 15: Test server1.py on port 5566
echo "Starting server1.py for testing on port 5566..."
nohup python3 server1.py > logs/server1_output.log 2>&1 &
SERVER_PID=$!
sleep 2  # Give it time to start

# Step 16: Verify server1.py is running
echo "Testing server1.py on port 5566..."
ss -tlnp | grep 5566 || echo "Port 5566 not listening"
ps aux | grep '[s]erver1.py'

# Step 17: Kill the test server
echo "Killing test server1.py..."
if [ -n "$SERVER_PID" ]; then
    kill -9 $SERVER_PID
    echo "Test server1.py (PID: $SERVER_PID) killed"
fi

# Step 18: Create server.sh for server.py
echo "Creating server.sh..."
cat << 'INNER_EOF' > /root/server.sh
#!/bin/bash
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Activating virtual environment..."
    source /root/nfcrelay-venv/bin/activate
fi

# Check and kill existing server.py process on port 5566
PORT_CHECK=$(ss -tlnp | grep 5566)
if [ -n "$PORT_CHECK" ]; then
    PID=$(ps aux | grep '[s]erver.py' | awk '{print $2}')
    if [ -n "$PID" ]; then
        kill -9 $PID
        echo "Killed existing server.py (PID: $PID)"
    fi
fi

cd /root/server1
nohup python3 server.py > logs/server_output.log 2>&1 &
echo "Started server.py on port 5566"
INNER_EOF

# Step 19: Create server1.sh for server1.py
echo "Creating server1.sh..."
cat << 'INNER_EOF' > /root/server1.sh
#!/bin/bash
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Activating virtual environment..."
    source /root/nfcrelay-venv/bin/activate
fi

# Check and kill existing server1.py process on port 5566
PORT_CHECK=$(ss -tlnp | grep 5566)
if [ -n "$PORT_CHECK" ]; then
    PID=$(ps aux | grep '[s]erver1.py' | awk '{print $2}')
    if [ -n "$PID" ]; then
        kill -9 $PID
        echo "Killed existing server1.py (PID: $PID)"
    fi
fi

cd /root/server1
nohup python3 server1.py > logs/server1_output.log 2>&1 &
echo "Started server1.py on port 5566"
INNER_EOF

# Step 20: Make scripts executable
echo "Making scripts executable..."
chmod +x /root/server.sh
chmod +x /root/server1.sh

# Step 21: Prompt user to choose which server to launch
echo "Setup complete. Which server would you like to launch?"
echo "1) server.sh (port 5566 - server.py)"
echo "2) server1.sh (port 5566 - server1.py)"
echo "Note: Both servers use port 5566, so only one can run at a time."
read -p "Enter 1 or 2: " choice

case $choice in
    1)
        /root/server.sh
        echo "Launched server.sh (server.py on port 5566)"
        ;;
    2)
        /root/server1.sh
        echo "Launched server1.sh (server1.py on port 5566)"
        ;;
    *)
        echo "Invalid choice. Run ./server.sh or ./server1.sh manually later."
        ;;
esac
EOF
