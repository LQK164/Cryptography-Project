import threading
import socket
import hashlib , binascii, base64
import sys, os , pickle
from Support import cpabe
from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from Crypto.Cipher import AES
from Support.curve25519 import *
from tabulate import tabulate

# Generate session keys
global session_public_key
global session_secret_key
global session_server_public_key
session_secret_key = os.urandom(32)
session_public_key = base_point_mult(session_secret_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 10000))

# Key agreement with server
client.send(b'@ecdh ' + binascii.hexlify(session_public_key.encode()))

def Help():
    options = """
    ------------------------ WELCOME TO HOSPITAL ---------------------------
    /register <username> <password>   : register
    /login <username> <password>      : login
    /create <group name>              : create group
    /join <group id>                  : join a group
    /key <group id>                   : get group public key for encryption
    /upload <group id>                : upload file to a group
    /download <group id> <file name>  : download file from a group
    /views                            : view all your groups
    ------------------------------------------------------------------------
    """
    print(options)


def AESDecryption(message):
    shared_secret = multscalar(session_secret_key, bytes.fromhex(session_server_public_key).decode())
    key = hashlib.sha256(shared_secret.encode()).digest()
    message = bytes.fromhex(message)
    authTag = message[:16]
    nonce = message[16:32]
    ciphertext = message[32:]
    encobj = AES.new(key,  AES.MODE_GCM, nonce)
    return(encobj.decrypt_and_verify(ciphertext, authTag))

def ViewsData(data):
    to_print = [0]*(len(data)-1)
    files = data[len(data)-1].split('\n')
    for i in range(len(data)-1):
        groupfile = []
        for f in files:
            if f.startswith(str(data[i][0])):
                groupfile.append(f)
            else: 
                continue
        data[i] += ('\n'.join(groupfile),) 
    for i in range(0,len(data)-1):
        to_print[i] = [data[i][0],data[i][1],data[i][2],data[i][3]]
    print(tabulate(to_print,headers=["Group ID","Group Name","Role","Files"],stralign="center",tablefmt="grid"))
    print("Press Enter to continue...")
    return

def client_receive():
    global isAuth
    global receivedpk
    global session_server_public_key

    while True:
        try:
            message = client.recv(4096*4).decode('utf-8')
            if(message):
                if message.startswith('Logged in.'):
                    isAuth = True
                    print(f"[NOTI] : {message}")

                elif message.startswith('eJy'):
                    print("[NOTI] : Received public key for encryption")
                    receivedpk = message.encode()

                elif message.startswith('@views'):
                    msg = message.split('@views ')[1].encode()
                    data = binascii.unhexlify(msg)
                    data = pickle.loads(binascii.unhexlify(msg))
                    print("[Info] : ")
                    ViewsData(data)

                elif message.startswith('ecdh'):
                    session_server_public_key = message.split(' ')[1]

                elif message.startswith('@sk'):
                    # Get secret key
                    secretKey = message.split('@sk ')[1].split('@pk ')[0]
                    secretKey = cpabe.bytesToObject(binascii.unhexlify(AESDecryption(secretKey)), cpabe.groupObj)

                    # Get group's public key
                    publicKey = message.split('@sk ')[1].split('@pk ')[1].split('@file ')[0]
                    publicKey = cpabe.bytesToObject(bytes.fromhex(publicKey), cpabe.groupObj)

                    # Get file name
                    filename = message.split('@sk ')[1].split('@pk ')[1].split('@file ')[1].split(' ')[0]

                    # Get file content
                    filecontent = message.split('@sk ')[1].split('@pk ')[1].split('@file ')[1].split(' ')[1]

                    # Get doctor ID
                    doctorId = message.split('@sk ')[1].split('@pk ')[1].split('@file ')[1].split(' ')[2]

                    # Decrypt
                    decrypted = cpabe.ABEdecryption(filecontent, publicKey, secretKey)

                    if(decrypted):
                        with open(f'./Downloads/{doctorId}_{filename.replace(".scd","")}','wb') as f:
                            f.write(decrypted)
                        print("[NOTI] : File downloaded")
                    else:
                        print("[NOTI] : You are not allowed to download this file")
                else:
                    print(f"[NOTI] : {message}")
            else:
                pass
        except Exception as error:
            print('Error!', error)
            client.close()
            break

    
def encrypt():
    global encrypted
    global encrypted_file_name
    global receivedpk
    
    filepath = input("[+] Enter path to file : ")
    policy = input("[+] Please provide policy for encryption : ")
    publicKey = cpabe.KeyFromBytes(receivedpk)
    encrypted, encrypted_file_name = cpabe.ABEencryption(filepath, publicKey, policy)
    return


def handle_input(message : str):
    if(message):
        global encrypted
        global encrypted_file_name
        
        if message.startswith('/register') or message.startswith('/login'):
            msg = message.split(' ')
            prefix = msg[0]
            username = msg[1]
            password = msg[2]
            salt = password[2:6]
            hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())

            if prefix == '/register':
                to_send = f"@register {username} {hashed.decode()}"
            else:
                to_send = f"@login {username} {hashed.decode()}"
            return to_send.encode()
        
        if(isAuth):
            if message.startswith('/create'):
                msg = message.split(' ')
                groupName = msg[1]
                to_send = f"@create {groupName}"
                return to_send.encode()
            
            if message.startswith('/join'):
                msg = message.split(' ')
                groupId = msg[1]
                to_send = f"@join {groupId}"
                return to_send.encode()
            
            if message.startswith('/accept'):
                msg = message.split(' ')
                doctorId = msg[1]
                attributes = msg[2] # attributes format: A,B,C
                groupId = msg[3]
                to_send = f"@accept {doctorId} {attributes} {groupId}"
                return to_send.encode()
            
            if message.startswith('/reject'):
                msg = message.split(' ')
                doctorId = msg[1]
                to_send = f"@reject {doctorId}"
                return to_send.encode()
            
            if message.startswith('/key'):
                msg = message.split(' ')
                groupId = msg[1]
                to_send = f"@pk {groupId}"
                return to_send.encode()
            
            if message.startswith('/upload'):
                # Check if user has received public key from group
                if (len(receivedpk) > 0):
                    msg = message.split(' ')
                    groupId = msg[1]
                    enc_thread = threading.Thread(target = encrypt)
                    enc_thread.start()
                    enc_thread.join()
                    to_send = f"@upload {groupId} {base64.b64encode(encrypted_file_name).decode()} {base64.b64encode(encrypted).decode()}"
                    return to_send.encode()
                else:
                    print("[!] You must obtain your group's public key first")
                    return None
            
            if message.startswith('/download'):
                msg = message.split(' ')
                groupId = msg[1]
                filename = msg[2]
                to_send = f"@download {groupId} {filename}"
                return to_send.encode()
            
            if message.startswith('/views'):
                return message.replace('/views','@views').encode()
        else:
            print("[!] You must login first")     
            return None
    else:
        return None
    
def client_send():
    while True:
        message = handle_input(input(">> "))
        if(message):
            client.send(message)

def main():
    receive_thread = threading.Thread(target = client_receive)
    receive_thread.start()
    send_thread = threading.Thread(target = client_send)
    send_thread.start()

if __name__ == '__main__':
    global receivedpk
    global isAuth 
    global encrypted 
    global encrypted_file_name
    isAuth = False
    receivedpk = b''
    encrypted = ''
    encrypted_file_name = ''
    Help()
    main()