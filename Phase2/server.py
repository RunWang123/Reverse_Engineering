
import socket
def decrypt(a):
    decrypted_value = b""
    for byte in a:
        tmp2 = ((byte - 122) & (2**8-1)) ^ 117
        decrypted_value += (tmp2).to_bytes(length = 1,byteorder="little", signed=False)
    print("Receive:")
    print(decrypted_value.decode(errors = "ignore"))
    return decrypted_value
def encrypt(mess):
    encrypt_value = b''
    a = str.encode(mess)
    a = b"\x68\x78\x20\x40\x00\x00\x00\xcc\x01\x00\x00\x01\x00\x00\x00\x6A\x00\x00\x00\x9c\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00dJ\x00\x00\x02\x00\x00\x00\x00\x00" + a
    for byte in a:
        tmp2 = ((byte ^ 117) + 122) & (2**8-1)
        encrypt_value += (tmp2).to_bytes(length = 1,byteorder="little", signed=False)
    print("Sent:")
    print(encrypt_value)
    return encrypt_value
def server_program():
    # get the hostname
    host = "127.0.0.1"
    print(host)
    port = 8888  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024)
        decrypt(data)
        decrypted_value = b''
        if not data:
            # if data is not received break
            break
        mess = input(" -> ")
        conn.send(encrypt(mess))  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()