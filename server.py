import socket
import threading
import sqlite3
import random
import base64
from Support import cpabe
from Support.curve25519 import *
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT
import os
import binascii
from Crypto.Cipher import AES
import hashlib, pickle

# Initialize Server Socket
IP = '127.0.0.1'
PORT = 10000
SERVER_ENDPOINT = (IP, PORT)

clients = []
session = []
groups = []
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
server.bind(SERVER_ENDPOINT)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Set socket options
server.listen()

# Thread
# =========================================

# Send message to client
def send(message : str, client : socket.socket):
    client.send(message.encode())
    return

def register(username : str, password : str):
    doctorId = random.randint(0, 200)
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"insert into DOCTORS values ({doctorId},'{password}','{username}')")
    conn.commit()
    conn.close()
    return

def login(username : str, password : str):
    try:
        conn = sqlite3.connect('hospital.db')
        c = conn.cursor()
        c.execute(f"select password, doctorId from DOCTORS where username = '{username}'")
        passwd, id = c.fetchall()[0]
        conn.commit()
        conn.close()
        if passwd == password:
            return True, id
        return False, None
    except:
        return False, None

# Encrypt and decrypt message in mode AES_GCM (authenticated encryption)
def AESEncryption(message, key):
    encobj = AES.new(key, AES.MODE_GCM)
    ciphertext, authTag = encobj.encrypt_and_digest(message)
    return(ciphertext , authTag, encobj.nonce)

def AESDecryption(message):
    key = open('app-secret','rb').read().decode()
    message = bytes.fromhex(message)
    authTag = message[:16]
    nonce = message[16:32]
    ciphertext = message[32:]
    encobj = AES.new(bytes.fromhex(key),  AES.MODE_GCM, nonce)
    return(encobj.decrypt_and_verify(ciphertext, authTag))

def create_group(ownerId : int, groupName : str, publicKey : str, masterKey : str):
    groupId = random.randint(0,100) + 1000
    key = open('app-secret','rb').read().decode()
    (cipher, authTag, nonce) = AESEncryption(masterKey.encode(), bytes.fromhex(key))
    masterKey = binascii.hexlify(authTag + nonce + cipher).decode()
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"insert into GROUPS values ({groupId},{ownerId},'{groupName}','{publicKey}','{masterKey}')")
    conn.commit()
    c.execute(f"insert into DOCTOR_GROUP values ({groupId},{ownerId},'Owner','')")
    conn.commit()
    conn.close()
    groups.append({groupId:ownerId})
    return

def accept(doctorId : int, attributes : str, groupId : int):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(
        f"insert into DOCTOR_GROUP values ({groupId},{doctorId},'Member','{attributes}')"
    ) 
    conn.commit()
    conn.close()
    return 

def Setup():
    (pk, mk) = cpabe.Setup()
    (pkb, mkb) = cpabe.KeyToBytes(pk, mk)
    return pkb.decode(), mkb.decode()

def GetDictValue(param, dict):
    for i in dict:
      for key in i.keys():
         if key == param:
            return i[key]
         
def GetUser(id):
    for i in session:
        for key in i.keys():
            if i[key][0] == id:
                return key
         
def GetUsername(id : int):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"select username from DOCTORS where doctorId = {id}")
    username = c.fetchall()[0][0]   
    conn.commit()
    conn.close()
    return username

def GetGroup():
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"select groupId, ownerId from GROUPS")
    data = (c.fetchall())
    for i in data:
        groups.append({i[0]:i[1]})
    conn.commit()
    conn.close()

def SendPublicKey(groupId : int, client : socket.socket):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"select publicKey from GROUPS where groupId = {groupId}")
    pk = c.fetchall()[0][0]
    conn.commit()
    conn.close()

    # Send public key to client
    send(pk, client)
    return

def Upload(filecontent : bytes, filename : str, groupId : str):
    with open(f'./Storage/{groupId}_{filename}','wb') as f:
        f.write(filecontent)
    return

def Download(doctorId : int, filename : str , groupId : int, client : socket.socket):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(
        f"""select attribute from DOCTOR_GROUP DG, DOCTORS D 
            where DG.doctorId = D.doctorId and D.doctorId = {doctorId} and groupId = {groupId}"""
    )
    attribute = c.fetchall()[0][0].split(',')
    attribute_list = []
    for attr in attribute:
       attribute_list.append(attr.upper())
    conn.commit()
    c.execute(
       f"select publicKey, masterKey from GROUPS where groupId = {groupId}"
    )
    (gr_pk, gr_mk) = c.fetchall()[0]
    conn.commit()
    conn.close()

    # Get group's public key and generate user's secret key
    pk = cpabe.bytesToObject(gr_pk.encode(), cpabe.groupObj)
    decrypted_mk = AESDecryption(gr_mk)
    mk = cpabe.bytesToObject(decrypted_mk, cpabe.groupObj)
    user_sk = cpabe.KeyGen(pk, mk, attribute_list)

    # Get encrypted file content then encrypt UserSecretKey with shared secret
    encrypted_file_content = open(f'./Storage/{filename}','rb').read()
    secretkey = binascii.hexlify(cpabe.objectToBytes(user_sk, cpabe.groupObj))
    file_content = binascii.hexlify(encrypted_file_content).decode()
    client_pub = bytes.fromhex(GetDictValue(client, session)[1]).decode()
    shared_secret = multscalar(session_secret_key, client_pub)
    aes_key = hashlib.sha256(shared_secret.encode()).digest()
    (ciphertext, authTag, nonce) = AESEncryption(secretkey, aes_key)
    to_send = f'@sk {binascii.hexlify(authTag + nonce + ciphertext).decode()}@pk {binascii.hexlify(gr_pk.encode()).decode()}@file {filename} {file_content} {doctorId}'
    
    # Send back public key, private key and file to client
    send(to_send, client)
    return

def Views(doctorId : int, client : socket.socket):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(
        f"""select G.groupId, G.groupName , role from DOCTOR_GROUP DG, DOCTORS D , GROUPS G
        where DG.doctorId = D.doctorId and DG.groupId = G.groupId and D.doctorId = {doctorId}"""
    )  
    data = c.fetchall()  
    conn.commit()
    conn.close()
    dir_path = './Storage'
    files = []

    # Check if current path is a file
    for path in os.listdir(dir_path):
        for i in range(len(data)):
            if os.path.isfile(os.path.join(dir_path, path)):
                if path.startswith(str(data[i][0])):
                    files.append(path)

    filestring = ''
    for i in files:
        filestring += i + '\n'
    data.append(filestring)
    to_send = b"@views " + binascii.hexlify(pickle.dumps(data))
    client.send(to_send)
    return 

def IsUserInGroup(doctorId : int, groupId : int):
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(
        f"""select D.doctorId from DOCTOR_GROUP DG, DOCTORS D
        where DG.doctorId = D.doctorId and DG.groupId = {groupId} and D.doctorId = {doctorId}"""
    )
    data = c.fetchall()
    conn.commit()
    conn.close()

    if(data):
      return True
    
    return False

def handle_message(message : str, client : socket.socket):

    # Case registration
    if message.startswith("@register"):
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        send("Registered, please login.\nPress Enter to continue...", client)
        register_thread = threading.Thread(target = register, args = [username, password])
        register_thread.start()
        return f"{username} registered!"
    
    # Case login
    if message.startswith("@login"):
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged, id = login(username, password)

        if(logged):
            for _client in session:
                for key in _client.keys():
                    if key == client:
                        _client[key][0] = id

            send("Logged in.\nPress Enter to continue...", client)
            return f"{username}#{id} signed in"
        else:
            send("This account does not exists", client)
            return None

    # Case creating group    
    if message.startswith('@create'):
        msg = message.split(' ')
        groupName = msg[1]
        publicKey, masterKey = Setup()
        ownerId = int(GetDictValue(client, session)[0])
        username = GetUsername(ownerId)

        # Send message to client
        send(f"You created group {groupName}", client)

        create_thread = threading.Thread(target = create_group, args = [ownerId, groupName, publicKey, masterKey])
        create_thread.start()
        return f"{username}#{ownerId} created group {groupName}"
    
    # Case joining group
    if message.startswith('@join'):
        msg = message.split(' ')
        groupId = msg[1]
        ownerId = GetDictValue(int(groupId), groups)
        owner = GetUser(ownerId)
        doctorId = int(GetDictValue(client, session)[0])
        username = GetUsername(doctorId)

        # Send message to client
        send(f"Group {groupId} join request from {username} #{doctorId}\n", owner)
        send(f"Use '/accept <doctorID> <attributes> <groupId>' to add member to group and give attributes\nUse '/reject <doctorId>' to reject join request", owner)
        return None
    
    # Case accepting joining request
    if message.startswith('@accept'):
        msg = message.split(' ')
        memberId = int(msg[1])
        attributes = msg[2]
        groupId = int(msg[3])
        senderId = int(GetDictValue(client, session)[0])
        ownerId = GetDictValue(groupId, groups)
        member = GetUser(memberId)

        if senderId == ownerId:
            accept_thread = threading.Thread(target = accept, args = [memberId, attributes, groupId])
            accept_thread.start()
            send(f"Your request to join group #{groupId} is accepted", member)
        else:
            send("You are not the group owner!", client)
        return None
    
    # Case rejecting joining request
    if message.startswith('@reject'):
        msg = message.split(' ')
        receiverId = int(msg[1])
        receiver = GetUser(receiverId)
        send("Your request is rejected!", receiver)
        return None
    
    # Case requesting group's public key
    if message.startswith('@pk'):
        msg = message.split(' ')
        groupId = int(msg[1])
        doctorId = int(GetDictValue(client, session)[0])
        if IsUserInGroup(doctorId, groupId):
            SendPublicKey(groupId, client)
            return "Public key is sent"
        else:
            send("You are not the group member!", client)
            return None

    # Case uploading file
    if message.startswith('@upload'):
        msg = message.split(' ')
        groupId = msg[1]
        filename = base64.b64decode(msg[2].encode()).decode()
        encrypted = base64.b64decode(msg[3].encode())
        savefile_thread = threading.Thread(target = Upload, args = [encrypted, filename, groupId])
        savefile_thread.start()
        savefile_thread.join()
        send("File uploaded", client)
        return None
    
    # Case key agreement with client
    if message.startswith('@ecdh'):
        pub_key = message.split(' ')[1]
        session.append({client:['',pub_key]})
        send('ecdh ' + binascii.hexlify(session_public_key.encode()).decode(), client)
        return None
    
    # Case downloading file
    if message.startswith('@download'):
        msg = message.split(' ')
        groupId = int(msg[1])
        filename = msg[2]
        doctorId = int(GetDictValue(client, session)[0])

        if IsUserInGroup(doctorId, groupId):
            down_thread = threading.Thread(target = Download, args = [doctorId, filename, groupId, client])
            down_thread.start()
            down_thread.join()
            username = GetUsername(doctorId)
            return f"{username} downloaded {filename} from group {groupId}"
        else:
            send("You are not group member!", client)
            return None
    
    # Case viewing information of user in group
    if message.startswith('@views'):
        doctorId = int(GetDictValue(client, session)[0])
        view_thread = threading.Thread(target = Views, args = [doctorId, client])
        view_thread.start()
        view_thread.join()
        return None
    else:
      return message

def handle_client(client : socket.socket):
  while True:
      try:
          message = client.recv(4096)
          msg = handle_message(message = message.decode(), client = client)

          if(msg):
            print(f"[LOG] : {msg}")
      except:
          clients.remove(client)
          client.close()
          break

def listen():
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target = handle_client, args=(client,))
        thread.start()
        clients.append(client)

def main():
    print('-------------- LISTENING ---------------')
    GetGroup()
    listen()

if __name__ == '__main__':
    global session_public_key
    global session_secret_key
    session_secret_key = os.urandom(32)
    session_public_key = base_point_mult(session_secret_key)
    main()