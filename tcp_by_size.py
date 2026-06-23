from secure_session import SecureSession_AES

class recvSend:

    def __init__(self,sock,key):
        self.SIZE_HEADER_FORMAT = "0000000|"
        self.size_header_size = len("0000000|")
        self.TCP_DEBUG = True
        self.LEN_TO_PRINT = 100
        self.sock = sock
        self.key = key
        if key is not None:
            self.aes_key = SecureSession_AES(key)

    def recv_by_size(self):
        size_header = b''
        data_len = 0
        while len(size_header) < self.size_header_size:
            _s = self.sock.recv(self.size_header_size - len(size_header))
            if _s == b'':
                size_header = b''
                break
            size_header += _s
        data  = b''
        if size_header != b'':
            data_len = int(size_header[:self.size_header_size - 1])
            while len(data) < data_len:
                _d = self.sock.recv(data_len - len(data))
                if _d == b'':
                    data  = b''
                    break
                data += _d

        if  self.TCP_DEBUG and size_header != b'':
            print ("\nRecv(%s)>>>" % (size_header,), end = '')
            print ("%s"%(data[:min(len(data),self.LEN_TO_PRINT)],))
        if data_len != len(data):
            data=b''

        if self.key is None:
            return data

        data = self.aes_key.decrypt(data)
        return data



    def send_with_size(self,bdata):
        if type(bdata) == str:
            bdata = bdata.encode()
        len_data = len(bdata)
        header_data = str(len_data).zfill(self.size_header_size - 1) + "|"

        # bytea = bytearray(header_data,encoding='utf8') + bdata

        if self.key is None:
            to_send = bytearray(header_data,encoding = 'utf-8')+bdata
            self.sock.send(to_send)
        else:
            bdata = self.aes_key.encrypt(bdata)
            len_data = len(bdata)
            header_data = str(len_data).zfill(self.size_header_size-1) + "|"
            to_send = bytearray(header_data, encoding='utf-8') + bdata
            self.sock.send(to_send)

        if self.TCP_DEBUG and  len_data > 0:
            print ("\nSent(%s)>>>" % (len_data,), end='')
            print ("%s"%(to_send[:min(len(to_send),self.LEN_TO_PRINT)],))

