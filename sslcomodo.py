import socket
import struct
import sys
import hashlib
import binascii

# Comodo FLS Constants
FLS_HOST = "fls.security.comodo.com"
FLS_PORT = 4447

# OpenEDR Packet Enums
RequestType_SimpleRequest = 0
HashType_SHA1 = 0
Protocol_Version = 3
ApplicationId_CloudAntivirus = 10
CallerType_FromOnAccess = 1

# OpenEDR Verdict Codes map
VERDICTS = {
    0: "MALWARE",
    1: "SAFE",
    2: "UNRECOGNIZED",
    3: "UNKNOWN",
}

def get_fls_verdict(file_path):
    try:
        # Calculate SHA1
        sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        hash_hex = sha1.hexdigest()
        hash_bytes = binascii.unhexlify(hash_hex)
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return

    # 1. Prepare Header
    # struct format: < B I B B B B 16s B
    # <   = Little Endian
    # B   = uint8  (requestType)
    # I   = uint32 (nId)
    # B   = uint8  (nNumOfHashes)
    # B   = uint8  (hashType)
    # B   = uint8  (nProtocol)
    # B   = uint8  (applicationId)
    # 16s = char[] (guid = 16 empty zeroes)
    # B   = uint8  (callerType)
    
    nId = 1337  # Arbitrary transaction ID
    header = struct.pack('<B I B B B B 16s B',
        RequestType_SimpleRequest,
        nId,
        1,              # numOfHashes
        HashType_SHA1,
        Protocol_Version,
        ApplicationId_CloudAntivirus,
        b'\x00' * 16,   # zeroed GUID (Anonymity!)
        CallerType_FromOnAccess
    )

    # 2. Append Hash Payload
    # We append the 20 byte raw SHA1 hash to complete the UDP packet
    packet = header + hash_bytes

    print(f"[*] Querying Comodo FLS via Anonymous UDP")
    print(f"[*] Target : {file_path}")
    print(f"[*] SHA-1  : {hash_hex}")
    print(f"[*] Packet : {len(packet)} bytes (Tracking ID explicitly zeroed)")

    # 3. Fire UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    try:
        sock.sendto(packet, (FLS_HOST, FLS_PORT))
        response, addr = sock.recvfrom(1024)
    except socket.timeout:
        print("[!] Comodo FLS UDP timeout.")
        return
    finally:
        sock.close()

    if len(response) < 5:
        print("[!] Response too small to be valid.")
        return

    # 4. Parse Response
    # Response length: nId(4) + nNumOfAnswers(1) + answers(2 bytes each)
    res_id, num_answers = struct.unpack('<I B', response[:5])
    
    if res_id != nId:
        print(f"[!] Security Mismatch: ID in response ({res_id}) does not match our request ({nId}).")
        return
        
    if num_answers != 1:
        print("[!] Server responded for different amount of hashes.")
        return
        
    answer_bytes = response[5:7]
    verdict_code = answer_bytes[0]
    
    verdict_str = VERDICTS.get(verdict_code, f"VERDICT_{verdict_code}")
    print(f"[+] ========================================")
    print(f"[+] COMODO FLS VERDICT : {verdict_str} (Code: {verdict_code})")
    print(f"[+] ========================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fls_client.py <file_to_scan>")
        sys.exit(1)
        
    get_fls_verdict(sys.argv[1])
