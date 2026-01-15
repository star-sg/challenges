from scapy.all import rdpcap
from Crypto.Cipher import AES
import struct
from impacket.smb3structs import SMB2Packet, SMB2Create, SMB2Create_Response, SMB2Read, SMB2Read_Response

PCAP = 'challenge.pcapng'
CLIENT_IP = '172.16.0.5'
ENC_KEY = bytes.fromhex('302b44f9bcacde386b78c3c89cfd9fd0')
DEC_KEY = bytes.fromhex('a035aa168d29d0cf2ac5e93238e5f7d1')

flag_mid = None
flag_fid = None
flag_read_mid = None
flag_data = bytearray()

for pkt in rdpcap(PCAP):
    tcp = pkt.getlayer('TCP')

    if not tcp or not tcp.payload:
        continue

    blob = bytes(tcp.payload)

    if blob[4:8] != b'\xfdSMB':
        continue

    header = blob[4:56]
    nonce = header[20:32]
    aad = header[20:]
    length = struct.unpack('<I', header[36:40])[0]
    cipher = AES.new(ENC_KEY if pkt['IP'].src == CLIENT_IP else DEC_KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    plain = cipher.decrypt_and_verify(blob[56:56 + length], header[4:20])

    smb = SMB2Packet(plain)
    cmd = smb['Command']
    mid = smb['MessageID']

    if cmd == 5:
        if smb['Flags'] & 1:
            if mid == flag_mid:
                flag_fid = SMB2Create_Response(smb['Data'])['FileID'].getData()
        else:
            name = SMB2Create(smb['Data'])['Buffer'].decode('utf-16le').lower()
            if 'flag' in name:
                flag_mid = mid

    if cmd == 8 and flag_fid:
        if smb['Flags'] & 1:
            if mid == flag_read_mid:
                flag_data.extend(bytes(SMB2Read_Response(smb['Data'])['Buffer']))
                break
        else:
            if SMB2Read(smb['Data'])['FileID'].getData() == flag_fid:
                flag_read_mid = mid

print(flag_data.decode())
