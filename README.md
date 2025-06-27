download https://github.com/Ghostfacexx/nfc/blob/main/nfc1.tar.gz

sudo tar -xzf nfc1.tar.gz -C /

cd server1
source "/root/nfcrelay-venv/bin/activate"
nohup python3 server1.py emvmanip
