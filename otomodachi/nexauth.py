import ctypes
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.serialization.pkcs12
import datetime
import os
import ssl
import tempfile
import os.path

class NexHttpCommunication:
    def __init__(self, dllfile):
        self.dll = ctypes.CDLL(dllfile)

    def NexHC_GetInnocentInfo(self):
        buff1 = ctypes.create_string_buffer(256)
        buff1_len = ctypes.c_int(256)
        buff2 = ctypes.create_string_buffer(256)
        buff2_len = ctypes.c_int(256)
        ret = self.dll.NexHC_GetInnocentInfo(buff1, ctypes.byref(buff1_len), buff2, ctypes.byref(buff2_len), None)

        certfile = buff1[:buff1_len.value:2].decode()
        password = buff2[:buff2_len.value:2]
        return certfile, password

    def NexHC_GetDeprecatedInfo(self, encrypted=False):
        buff1 = ctypes.create_string_buffer(256)
        buff1_len = ctypes.c_int(256)
        buff2 = ctypes.create_string_buffer(256)
        buff2_len = ctypes.c_int(256)
        mode = ctypes.c_int(1) if encrypted else ctypes.c_int(0)

        ret = self.dll.NexHC_GetDeprecatedInfo(buff1, ctypes.byref(buff1_len), buff2, ctypes.byref(buff2_len), mode, None)

        username = buff1.raw[:buff1_len.value].decode()
        password = buff2.raw[:buff2_len.value].decode()
        return username, password

    def NexHC_Decrypt(self):
        pass

    def NexHC_Encrypt(self):
        pass

    def NexHC_Encrypt2(self):
        pass

    def NexHC_GetVersion(self):
        pass

class NexAuth:
    def __init__(self, dllfile=None):
        if dllfile is None:
            dllfile = self.locate_dll()
        self.nexHttpCommunication = NexHttpCommunication(dllfile)

    def locate_dll(self):
        filenames = (
            'C:/Program Files (x86)/OMRON/Communications Middleware/assembly/NexHttpCommunication_x64.dll',
            './NexHttpCommunication_x64.dll',
        )

        for file in filenames:
            if os.path.isfile(file) and os.access(file, os.R_OK):
                return file
        raise ValueError('Cannot find NexHttpCommunication_x64.dll')


    def pkcs12_to_pem(self, pkcs12_file, pkcs12_password):
        with open(pkcs12_file, 'rb') as f:
            pkcs12_data = f.read()

        private_key, cert, ca_certs = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(
            pkcs12_data,
            pkcs12_password
        )
        
        pem = tempfile.NamedTemporaryFile(delete=False)

        # private key
        pem_private_key = private_key.private_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.PEM,
                    cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                    cryptography.hazmat.primitives.serialization.NoEncryption()
                )
        pem.write(pem_private_key)

        # certificate
        pem_certificate = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
        pem.write(pem_certificate)

        # CA certificates
        if ca_certs:
            for ca_cert in ca_certs:
                pem_ca_cert = ca_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
                pem.write(pem_ca_cert)

        pem.flush()
        pem.close()

        return pem.name

    def getCertificateFilename(self):
        pfxpath, pfxpass = self.nexHttpCommunication.NexHC_GetInnocentInfo()
        return self.pkcs12_to_pem(pfxpath, pfxpass)

    def getLogin(self, encrypted=False):
        return self.nexHttpCommunication.NexHC_GetDeprecatedInfo(encrypted)

    def dump(self, filename):
        login, passwd = self.getLogin(encrypted=False)
        encrypted_login, encrypted_passwd = self.getLogin(encrypted=True)
        certificate = self.getCertificateFilename()
        with open(certificate, 'r') as f:
            certificate_data = f.read()
        os.unlink(certificate)

        data = {
            'login': login,
            'password': passwd,
            'encrypted_login': encrypted_login,
            'encrypted_password': encrypted_passwd,
            'encrypted_certificate': certificate_data,
        }

        with open(filename, 'w') as file:
            file.write("data = " + repr(data))

