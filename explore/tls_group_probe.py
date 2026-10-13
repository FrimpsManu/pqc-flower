"""Start a gRPC TLS server (as Flower's SuperLink does) so openssl can probe which key-exchange groups it accepts."""

import sys
import time
from concurrent import futures

import grpc

cert, key = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
server.add_secure_port("127.0.0.1:50443", grpc.ssl_server_credentials([(key, cert)]))
server.start()
time.sleep(float(sys.argv[3]) if len(sys.argv) > 3 else 20)
