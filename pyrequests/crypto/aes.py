
import struct
from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )


class AES_GCM(object):

    def aes_encrypt(self, key, iv, aead, plaintext):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        encryptor.authenticate_additional_data(aead)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        #(iv, ciphertext, encryptor.tag)
        return ciphertext, encryptor.tag

    def aes_decrypt(self, key, iv, aead, ciphertext, tag):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv,tag),
        ).decryptor()
        decryptor.authenticate_additional_data(aead)

        a=decryptor.update(ciphertext)
        b=decryptor.finalize()
        #print(b)
        return a
if __name__ == '__main__':
    aes = AES_GCM()
    client_handshake_write_key =b'r\x0b\xc7\x89\x11U\x8cWZ\x83\xfd\xe1\xaaF\x177!l\xcd\x12_Uw\xef\x92\xe8)2{\x0cy\xd6'
    server_handshake_write_key = b'\xe9\xf6\xb51\xd6J\xc6\x06\x8d\x8c\x9dIe\x95O\xff\xc3n\xeb\x07\xdd.Q\xc1\x08\xef\xbaG\xc2\xa2\x19\xe6'
    client_app_write_key = b'|u\x02o\xbd\xed\x92_\x85\xd4J!\xca\xddHn\xf1\xb2\x8a\xcc\x8e\x8f7D\t]\xe3S\x95\xf7\x9b`'
    server_app_write_key = b'\x12K>9\x9b{Rb2\x0b\xa2k\xe4\xa1\xd9|\xe4<\xb9\x9d\x9b\x9c\xb9B\x1c\xe0\xb6\xc9\x12Z\xcbU'
    iv =b'\xfar\x0b\xc0\xa2\xe0\x9a\x9f\x0e$\xcc\xc1'

    server_ext=bytes.fromhex("c6fb7dcd44713b37accb9fdd405affd0b88c15521de892")
    server_ext = bytes.fromhex("2b37cb02d7d12b07715b47fd72cb7774db304baaa723775973a4e7c6be9a1b3a7d1c3e87227c3baa7cbfc07dea331897fa6434da135ec4b65d60bf28aadfdce336a5f31acec5ed687957fe7907d43a997422069787ea2f281e2eca7b44718b45004fb49fcb2adb3af7129fc4e9d4e66e05f7f6bd417eb0d8debc2a042b854e81af45dc9f63bf63028ca8883af6064ee8ef7c47f95c0b037758be8a6f658610bccd3794c12c0ff000bcd25fb1f44df6be293565caa932536225bafa859c4387632c76d313dc8171e599f4e29dc74001430daa57f01b50c7e86ac632dd09b53bb837059073b45be2978feba37b1825767d14b9f137c3cd9646657cb5ab6b1efd8a4bc75e3437374db5582dbdf80b28875a677a3d535bcb697429")

    client_finised = bytes.fromhex("ff0b00aa28f2272c3c493f090a3ebeb9c571d700d0310284872baab92ba436755d50d0ec06775c678ab01184c63fa1f500021e4bb9ece8fd0246196591d92170d2e3164a21")
    client_new_ticket = bytes.fromhex("592071bbb4270ce12dedb191e528f785f85a021a89c5ad7b45b25d2ee462d2f089a033ff990d48048879f56bd20b17d7d86d42207fd9ea980c7b90c4848cb733795691124b4e3bd63774cc3dd777056ebf310f03cc3b29ddf103af95973b6a90d72dc48be778ad5bb8f1b09e2765c4db20d9be2a15b9e25ffb87ebf36349174a2b3fc516456876256f4fc44274f56173a490053dcf11a5c1c0f3db705f0ed6b8b725b9f4bf6db1eedf96b8d0ac8bd0969591a2783c43faca09913a7aeb8f0396bbfdfc8b25950aec52ad7c5efaea68fb3e82b1251f65e2ebeca5161594af7972fb76832e89d0d01d6fd4ec0eb93516e0a92e5b7cb1f538f0ca6b")
    client_app=bytes.fromhex("972c3750edad9466c42736fcd84a1143d277e0a9f4d774c13b077d7c1104b662cb635f01e5089543feaa39b9dea045ea23f9295cbe3a93b66b745dcea28fe89586bc2a628d76ab7c3a2e1136b3a4720a8d08fcd61de4f2077c049e595de98164d65e8b57d5be87dfa56d7d53967f8f9a3d5574875b6e3b71c778a6b70987d5fa2cca318ff02dcd91a24e6595b06af396b9c37389e8013a68a9047f30a36632f4967c60fb0aceecc07f6c01a9bb2ffaf91fc97e795daf2e3b67471834cbb06764228533228500fa19d8d7d514bbd8002982d64349c25afbf9e74780b936016ccd9d3905c3a6c578342a082fdadecd18702e9eeb1ceee2a18071c10671134e2f143265c3167664bebb00441474636c94b790e9903c3f23f99249afb264ae5a64e4baf597ee23cae6a8ce6ecf0b772727ee9831bde86dd53a1fe126889d3ffc80c114a8f2503891e63b8acb6488950c43a413103f84afed1224a8e26e0b6ecb6bea8f12da6c67787d0296da9b255f266c2577aa7f2884b04f0be72aa9f867342ee8acc50b141748dc7e802c9b1f3716c3c8de3f7d8c122906cc73117c01e590a40874466a10c172beb136a97dd638acc1ac17a1efe98b74db768e8886f9300951b4e44c20abedaa7b6eeb88be28da10059f16336b187b24765d5faa471120f7612de4c38a97b1545e629c696136e3a9ef287db481cd66f3e9867979a490d6748bf87d824664b4770ff0c9d9cdf05945a5b2fe1ed6b302e329bf9042099ae0aaa85fb11f04baa253e003f97039abffd40111d09e89ffe2a37926f0e1808821d6f04190bc2b5dbe12cb540839212f0a50aa0e503df14da99e5dc31ceb65189949b96ef3c7de8c49449740644af6e8b0c5ac6b118390ce280e0f6f8eac314072c3202d1b41d932a331d7bb49e9bacb9869ca6ae2a1eed4336633800d2e95556c1c29ce51d1ade868a4c67d4f9dd0ac1a27ee0cf6ae80")
    server_app = bytes.fromhex("d174256cf02cce68e0b2d849b17aea9472ef7b")
    client_finished= bytes.fromhex("8e8b17bb62dfbd3b52ec8b0b86f37b94fb14be9496c7ea8717efa5d919bf1a53b54ab85655fbe26223cbaa5f0976858e0850d58996b542071d4302884eec9903ff8d5f93d7")

    aead = b'\x17\x03\x03' + struct.pack('!H',len(client_finised))
    text,tag = client_finised[:-16],client_finised[-16:]
    c, t = aes.aes_encrypt(server_app_write_key, iv, aead, text)
    plaintext = aes.aes_decrypt(client_handshake_write_key ,iv,aead,text,tag)
    print(c)
    plaintext = b'\x14\x00\x000\xa8\xcaG\xd2g\'\xc2\x1a\xf6w^\x11W\xf5f\x93\x0b\x1fO\x1dC\xb4*\'\xe0\xeal\xb2nF\x17\x96\x1a\xb5{v\x8d\x06\x15\x86=\x1f\xe3"\n_\xe5\xd6\x16'
    aead = b'\x17\x03\x03' + struct.pack('!H', len(plaintext)+16)
    ciphertext,tag = aes.aes_encrypt(client_handshake_write_key ,iv,aead,plaintext)
    print(client_finised.hex())
    print(ciphertext.hex(),tag.hex())

    p = aes.aes_decrypt(b'\xbd\x89\xe2\x983R\x85\xf1THD05\xc8$]\x9f}\x94\xc3\xb9@+P\xa4\x8c\xe5v\x91Y\x03\x80',
                        b'\xeb\xa9\xbdf\x07\xcf]4\x11\x05\xc88',
                        b'',
                        bytes.fromhex("ebe707fe72c0b8c409dc3d024abd051b1a3874780cc1f0a4783b3d66c7179fb68eaf6aca40ad8bac257a049dbb5dae8dba709e0bc07a53bcfa670a382dd4ea7776a01f4417d2b255481259cbe037bf087707800261655b99d8a4621e6fd0c9d4f6820d98c9574383cc3f65a4c174fd60f69033b4516d01f551a72536823167bbce8bcff1353757644ccd2f063527383e84ac62b17e8091bd9c90ee81457588b1385cf07d96d9385d4eb6a8d446d00294a3cb085291e60df1460b93a572d622b2c9e6f9e17a3f888b25c9ccb4d8d0b2e4c30e112bc3e1252a842f3497bcf4af8d5416e53e2fd09abf1f6a466468e10682dd5d536572925c3e2e5c2b820cb8abbb1c2f0b5ceed540c37f0438211ad4f49da0f4cb0e157fa5431663b7da7014cc8b6e048fbbc1adc00ef9f6104d9d8000951d8f036b43646905f019a7c935b2e16ee92a59c5c6efdc14fbf3d459a8c3d5ae0c8562d67ffead30eb808d597dec447ce6e41fb8eedd942db16ee6d589bbcd835b7eb47fc015eff30ac3a1a483f254dda44f21bdc74bf489dfede725fe8f54ade035b9cf47111ad8989030a51d7e29cc92d1f107503c7e50ac94863156fcffeed911dc467ddbcd60a96fcdaccd4c5f19d5a46b45482fd5a21b177de6e1ce570dbf809378322829d5e112901ded50c356b36f213c03995b835b8efcc976cbd9a5b8bb643e1a0490b0")[:-16],
                        tag
                        )

    print(p)








