import http
import http.server
import ssl
import tempfile
from hexdump import hexdump

def proxy_log(message, data):
    s = data.decode('ascii', errors='ignore')
    if s.isprintable():
        print(f'{message}: {s}')
    else:
        print(message)
        hexdump(data)

class ProxyHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    realplc = None
    
    def log_message(self, format, *args):
        return
    

    def filterHeaders(self, headers):
        res = {}
        for k, v in headers.items():
            if k.lower() not in ('host', 'content-length', 'connection'):
                res[k] = v
        return res
    
    def do_GET(self):
        print(f'GET {self.path}')
        r = self.realplc.http.get(self.path)

        self.send_response(r.status_code)
        self.send_header('Content-Length', len(r.content))
        self.send_header('Connection', 'Keepalive')
        # send other headers from original response
        headers = self.filterHeaders(r.headers)
        for header, value in headers.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(r.content)
        return

    def do_POST(self):
        
        self.filterHeaders(self.headers)
        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len)

        # log filter
        doLog = True
        s = post_body.decode('ascii', errors='ignore')
        for f in ('CPU_getStatus', 'CPU_getStatusExtend', 'CPU_getTaskInfo BaseTask', 'Memory_asyncRead'):
            if s.startswith(f):
                doLog = False
                break

        if doLog:
            print(f'POST {self.path}')
            proxy_log('POST request', post_body)

        req_headers = self.filterHeaders(self.headers)
        r = self.realplc.http.xpost(self.path, post_body, req_headers)
        
        if doLog:
            proxy_log('POST response', r.content)
        
        self.send_response(r.status_code)
        self.send_header("Content-Length", len(r.content))
        self.send_header("Connection", "Keepalive")
        # send other headers from original response
        headers = self.filterHeaders(r.headers)
        for header, value in headers.items():
            self.send_header(header, value)
        self.end_headers()
        
        self.wfile.write(r.content)
        return



def _gen_cryptography():
    import datetime
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    import socket

    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day*365*5))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(socket.gethostname()),
            x509.DNSName('*.%s' % socket.gethostname()),
            x509.DNSName('localhost'),
            x509.DNSName('*.localhost'),
        ]),
        critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend())

    return (certificate.public_bytes(serialization.Encoding.PEM),
        private_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

def proxy(bind, port, realplc):
    
    server_address = (bind, port)
    ProxyHttpRequestHandler.realplc = realplc
    httpd = http.server.HTTPServer(server_address, ProxyHttpRequestHandler)
    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    # openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout server.pem -out server.pem

    certfile = tempfile.NamedTemporaryFile(delete=False)
    cert, key = _gen_cryptography()
    certfile.write(cert)
    certfile.write(key)
    certfile.flush()
    certfile.close()
    ctx.load_cert_chain(certfile=certfile.name) #, keyfile="server.pem")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f'proxy running {bind}:{port} -> {realplc.host}')
    httpd.serve_forever()
