import Encryptor
import os
import struct


class Load:
    def __init__(self, buff):

        self.buff = buff
        self.client = None

        # 初始化加密器
        self.encryptor_generator = Encryptor.AES_MD5()

    def setClient(self, client):
        self.client = client

    def upload(self, file_path):

        file_length = os.path.getsize(file_path)

        spilt_num = file_length // self.buff
        end_length = file_length - spilt_num * self.buff
        hash_code = self.encryptor_generator.getMd5(file_path)

        self.sendInfo(str(spilt_num))
        self.sendInfo(str(end_length))
        self.sendInfo(hash_code)


        if file_length != 0:
            try:
                with open(file_path, 'rb') as f:
                    count = 0
                    while True:
                        if count == spilt_num:
                            line = f.read(end_length)
                            encrypt_line = self.encryptor_generator.encrypt_bin(line)
                            self.client.send(encrypt_line)
                            return
                        else:
                            line = f.read(self.buff)
                            encrypt_line = self.encryptor_generator.encrypt_bin(line)
                            self.client.send(encrypt_line)

                        count += 1
            except IOError as error:
                print('upload error:' + str(error))


    def download(self, file_path):

        if os.path.exists(file_path):
            os.remove(file_path)

        spilt_num = int(self.receiveInfo())
        end_length = int(self.receiveInfo())
        remote_hash_code = self.receiveInfo()

        if spilt_num == 0 and end_length == 0:
            with open(file_path, 'ab') as f:
                f.write(b'')
                return

        block = self.buff + 16

        count = 0
        while True:
            try:
                if count == spilt_num:
                    receive = self.client.recv(end_length + 16)
                    decrypt_line = self.encryptor_generator.decrypt_bin(receive)
                    with open(file_path, 'ab') as f:
                        f.write(decrypt_line)
                    return
                else:
                    receive = self.client.recv(block)
                    decrypt_line = self.encryptor_generator.decrypt_bin(receive)
                    with open(file_path, 'ab') as f:
                        f.write(decrypt_line)
            except IOError as error:
                print('download error:' + str(error))
                return
            count += 1

    # 发送的就是加密的信息
    def sendInfo(self, text):
        text = text.encode()
        text = self.encryptor_generator.encrypt_bin(text)
        text_length = len(text)

        self.client.send(struct.pack('i',text_length))
        self.client.send(struct.pack(str(text_length) + 's', text))

    def receiveInfo(self):

        text_length = self.client.recv(4)
        text_length = struct.unpack('i', text_length)[0]
        text = self.client.recv(text_length)
        text = struct.unpack(str(text_length) + 's', text)
        text = text[0]
        text = self.encryptor_generator.decrypt_bin(text)
        text = text.decode()
        return text
