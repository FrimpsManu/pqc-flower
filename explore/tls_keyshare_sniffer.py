"""Relay between a farm and the SuperLink that reports the TLS key-exchange groups on the wire.

Reads the ClientHello (groups the farm offers) and the ServerHello (group the server picks).
Usage: tls_keyshare_sniffer.py LISTEN_PORT TARGET_PORT
"""

import socket
import struct
import sys
import threading

GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "X25519", 0x001E: "X448",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
name = lambda g: GROUPS.get(g, f"0x{g:04x}")


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


def read_record(sock):
    header = read_exact(sock, 5)
    return header, read_exact(sock, struct.unpack(">H", header[3:5])[0])


def extensions(hello, is_client):
    i = 4 + 2 + 32  # handshake header, version, random
    i += 1 + hello[i]  # session id
    if is_client:
        i += 2 + struct.unpack(">H", hello[i : i + 2])[0]  # cipher suites
        i += 1 + hello[i]  # compression methods
    else:
        i += 2 + 1  # chosen cipher suite, compression method
    end = i + 2 + struct.unpack(">H", hello[i : i + 2])[0]
    i += 2
    while i < end:
        ext_type, ext_len = struct.unpack(">HH", hello[i : i + 4])
        yield ext_type, hello[i + 4 : i + 4 + ext_len]
        i += 4 + ext_len


def report_client_hello(body):
    for ext_type, data in extensions(body, is_client=True):
        if ext_type == 10:  # supported_groups
            groups = [struct.unpack(">H", data[j : j + 2])[0] for j in range(2, len(data), 2)]
            print("farm offers (supported_groups):", ", ".join(map(name, groups)), flush=True)
        if ext_type == 51:  # key_share
            j, shares = 2, []
            while j < len(data):
                group, length = struct.unpack(">HH", data[j : j + 4])
                shares.append(f"{name(group)} ({length} B)")
                j += 4 + length
            print("farm sends key shares for:", ", ".join(shares), flush=True)


def report_server_hello(body):
    for ext_type, data in extensions(body, is_client=False):
        if ext_type == 51:
            group, length = struct.unpack(">HH", data[:4])
            print(f"server picks: {name(group)} (key share {length} B)", flush=True)


def pipe(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        dst.close()


def handle(client, target_port):
    upstream = socket.create_connection(("127.0.0.1", target_port))
    header, body = read_record(client)
    report_client_hello(body)
    upstream.sendall(header + body)
    header, body = read_record(upstream)
    report_server_hello(body)
    client.sendall(header + body)
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    pipe(upstream, client)


def main():
    listen_port, target_port = int(sys.argv[1]), int(sys.argv[2])
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen_port))
    server.listen()
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client, target_port), daemon=True).start()


if __name__ == "__main__":
    main()
