
"""
TLS session handler.
"""

import socket
import struct
import hashlib
from copy import deepcopy
import gzip
import time
import warnings



from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


from pyrequests.layers.tls.keyexchange import SessionContext,ServerContext,ClientCpiherSpec,ClientKeyExchange,KeyStore
from pyrequests.layers.tls.handshake import HelloClient
from pyrequests.layers.tls.suites import CipherSuites
from pyrequests.layers.tls.extensions import dump_extension

from pyrequests.layers.tls.crypto.prf import prf
from pyrequests.layers.tls.crypto.aes import AES_GCM
from pyrequests.layers.tls.crypto.ecc import CryptoContextFactory

from pyrequests.models import Response



# expire_stamp = 1657074207
# if time.time() -expire_stamp > 7*24*3600:
#     raise BaseException('很抱歉,测试版本已到期,详情到项目地址: https://github.com/zero3301/pyrequests')


class TlsSession():
    def __init__(self, ja3=None,**kwargs):
        self.sc = SessionContext()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servercontext = ServerContext()
        self.ja3 = ja3
        self._closed = True


    @property
    def isclosed(self):
        return getattr(self, '_closed')

    @isclosed.setter
    def isclosed(self, value):
        setattr(self, '_closed', value)


    def connect(self, host, port):
        self.sc.verify_data = []
        self.host, self.port = host, port
        self.t1 = time.time()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)


        #recv超时设置
        #self.socket.settimeout()

        try:

            self.socket.connect((host, port))
        except ConnectionRefusedError:
            warnings.warn('无法连接 %s' % self.host)
            return False
        else:
            self.local_ip, self.local_port = self.socket.getsockname()[:2]
            self.remote_ip, self.remote_port = self.socket.getpeername()[:2]


            #print('客户端地址: %s:%s' % (self.local_ip, self.port))
            #print('服务器地址: %s:%s' % (self.remote_ip, self.remote_port))
            self.isclosed = False

            return self._tls_do_handshake()


    def _tls_do_handshake(self):

        ciphersuites, extensions = CipherSuites().dump(),dump_extension(self.host,ja3=self.ja3)
        hello = HelloClient(ciphersuites, extensions)
        self.socket.send(hello.dump(self.sc))


        self.client_seq = 0
        self.server_seq = 0

        exchanage  = True
        cache =b''

        while True:
            recv = self.socket.recv(8126)
            recv = cache + recv
            cache = b''
            if recv:
                while recv:
                    handshake_type = struct.unpack('!B', recv[:1])[0]
                    length = struct.unpack('!H', recv[3:5])[0]
                    flowtext = recv[5:5 + length]

                    if len(flowtext) != length:
                        cache = deepcopy(recv[:])
                        break

                    if handshake_type == 0x16:
                        self.sc.verify_data.append(flowtext)
                        self.servercontext.load(flowtext)

                    elif handshake_type == 0x14:
                        self.server_seq +=1
                        #print('握手完成')
                        return True
                    #warnings.warn('fail')
                    elif handshake_type == 0x15:


                        warnings.warn('握手失败,Description: Decrypt Error (%s)' % flowtext)
                        raise ConnectionError('handshake failed')
                    recv = recv[5+length:]

                if self.servercontext.done and exchanage:

                    # publickey_bytes = CryptoContextFactory.crypto_container['x25519'].client_kx_privkey.public_key().public_bytes(
                    #     serialization.Encoding.Raw,
                    #     serialization.PublicFormat.Raw
                    # )
                    # pms = CryptoContextFactory.crypto_container['x25519'].client_kx_privkey.exchange(
                    #     x25519.X25519PublicKey.from_public_bytes(servercontext.serverpubkey))

                    from cryptography.hazmat.primitives.asymmetric import ec as cg_ec
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import serialization, hashes

                    client_kx_privkey = CryptoContextFactory.crypto_container['secp256r1'].client_kx_privkey

                    server_publickey = cg_ec.EllipticCurvePublicKey.from_encoded_point(
                        cg_ec.SECP256R1(),
                        self.servercontext.serverpubkey
                    )
                    pms = client_kx_privkey.exchange(cg_ec.ECDH(), server_publickey)


                    publickey_bytes = client_kx_privkey.public_key().public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint
                    )

                    keychange = ClientKeyExchange(publickey_bytes).dump(self.sc)
                    changecipherspec =  ClientCpiherSpec().dump()


                    self.keystore = KeyStore().load(pms, hello.hanshake, self.servercontext.serverstore)
                    explicit_nonce = struct.pack('!Q',self.client_seq)

                    nonce = self.keystore.client_fixed_iv +  explicit_nonce
                    handshake = hashlib.sha256(b''.join(self.sc.verify_data)).digest()
                    label = b"client finished"
                    for i in self.sc.verify_data:
                        #print(i.hex())
                        pass

                    self.sc.verify_data = []
                    plaintext = prf(self.keystore.masterSecret, label + handshake, outlen=12)

                    plaintext = b'\x14\x00\x00\x0c' + plaintext
                    # 附加数据
                    aead = explicit_nonce + b'\x16\x03\x03' + struct.pack('!H', len(plaintext))
                    aes = AES_GCM()

                    ciphertext, tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
                    ciphertext = explicit_nonce + ciphertext + tag

                    encrypted_message = b'\x16' + b'\x03\x03' + struct.pack('!H', len(ciphertext )) + ciphertext
                    #self.socket.send(encrypted_message)
                    self.socket.send(keychange + changecipherspec + encrypted_message)
                    self.client_seq += 1
                    exchanage = False



    def send(self, plaintext):

        #print('tlssession send', plaintext)
        #plaintext = b'GET / HTTP/1.1\r\nHost: www.ihg.com.cn\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n'
        #s='504f5354202f4461666a5f582f786f482f4b356e2f53636d3738772f6d397075665662362f486a5931485655422f466d45552f506e4d415a467720485454502f312e310d0a486f73743a207777772e6968672e636f6d2e636e0d0a557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e5420362e333b20574f5736343b2072763a33342e3029204765636b6f2f32303130303130312046697265666f782f33342e300d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a207a682d636e2c7a683b713d302e382c656e2d75733b713d302e352c656e3b713d302e330d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a414452554d3a206973416a61783a747275650d0a436f6e74656e742d547970653a20746578742f706c61696e3b20636861727365743d5554462d380d0a507261676d613a206e6f2d63616368650d0a43616368652d436f6e74726f6c3a206e6f2d63616368650d0a526566657265723a2068747470733a2f2f7777772e6968672e636f6d2e636e2f686f74656c732f636e2f7a682f7265736572766174696f6e0d0a436f6e74656e742d4c656e6774683a20313638340d0a436f6f6b69653a20616b616d6169436f756e747279436f64653d434e3b20616b616d61694973576972656c6573734465766963653d66616c73653b20616b616d616949735461626c65743d66616c73653b20582d4948472d54727565436c69656e745f49503d3131332e38392e3234352e3230313b20726f6f6d4b6579436f6f6b69653d313635373030313632333b20436f70746572436f6e6e6563743d42323239424237382d363545422d343132382d393536322d3642454334344131383131462537436165303230643430373037336337653731316635363439656639383434656334253743494847526f6f6d6b6579706f703b205f6162636b3d45413735304445323846373531433537384145353837334531353639314643347e307e59414151486f7955477852414e704f424151414144597a2b7a41696e6c37664f4f36354878495a566848714b4f5a774c306d587630386243636b732f5a45442f4e3463414169512f5361306c374d6633393879495a7551534566566e7761692b77554859386a317745476a2b626831567965733052385362466a4967334b3937772b35505639433941756c6c374e586e6e6d2b2b786b7379433863466f4d657a61775155706e64516970393535595071586657762f5731495a3773666e666f4e6e4e437a6a4770415359594b46704d493449664550504732636439686237694b6d53624a2b6f392f73664465436f614a6d3447614d7a66697259436557565962497965344e773854496a36724a2b6f5a4864674c2f3747497048332b4637307a4f4c647862386a3746312b323851306f3662643678536a65496436482f7a763774527a5179436d66684d7a65577674502f7835783477566f6b7a4577354d67537253616c46374b456f546746386d7a4f326f65714c3670585237622b33385574654435774a394e7a354b6a7a37437a4e42514463524d4b6b666d63344e6b677369513d3d7e2d317e2d317e2d313b20626d5f737a3d32394536434237453834423244353734313932453842313344444237323834387e59414151486f7955473741784e704f4241514141416b442b7a424172662f6331615234534a334434487979325263687262467455394279636d6e52586f556d39654c55336c43735352744b6a4a5242704364716a4c567134433162336d5730423442716374482b33383754704a336536684476386b3255415272735258493149727a516c424f6b45445773485852757a423652394f6e707a4f4e4d6a487659583947795a537759726c2b66574c767168684b50357763647753682f4d35364b4939706e5030424f38594c582f446c6b705652474463346f4159657356446a34376b4e4a2b39547778676d7a4f72724678497663694e63336e3971616d316b746e6a426e5239556c3238327732744759614972456875593672687241557465614a4738795a376e2f794e31336e6977513d7e333232343133337e343533363337363b20616b5f626d73633d30384231453546343532304341373541334330443936364432314441333639427e3030303030303030303030303030303030303030303030303030303030307e59414151486f7955473773784e704f42415141415545442b7a424174724c6b62496b55784265324e554f4f4d5a55743934413044344e304a4a64574f316c634932567a394d43754644305a692f3054576561334a592b644c4636394342555867416934464e75716935362f7954504549504f2f71347873774f796a4a596f5743424e72725339594f4f5772303942323862385855754a33743257614251333254594b4862485a4d64744d4c374a6e70426a576a644753496f2b45424a3571586f6244346c7a4d51737661744262354e4839705065686e713132666545786a43545a6251626a7669484d414a3561365369377556474f505432794d39394c2f692b7458492f2f6a63697947347471684e596d557737396f46707142566b6a31634566595a514c2f384d3856426d316577477062484a377630583769436b724d6a4e644a32785735657461594673594e6c386e724d313031524c544c75656d316f67494a384131457774322b394d71614b45786b2f7a7857536176786e626e79376830515a344a7032466f44746f2f625868426b413d3b20616b61616c625f7230385f70726f643d7e6f703d4c425f7230385f4265696a696e675f70726f643a705f726f757465725f4265696a696e677c7e72763d39337e6d3d705f726f757465725f4265696a696e673a307c7e6f733d34643666383837623334663064356539666265663139613339396366636366667e69643d35356438393030613063623030326263626233653939643064663362376531663b2076696577706f72743d6c617267653b206f7269656e746174696f6e3d6c616e6473636170653b20616b61616c625f766e645f70726f643d7e6f703d4c425f76656e646f725f4265696a696e675f70726f643a705f726f757465725f4265696a696e677c7e72763d32397e6d3d705f726f757465725f4265696a696e673a307c7e6f733d34643666383837623334663064356539666265663139613339396366636366667e69643d65646663636233303537666630663633643232386439616166633863336338313b20626d5f73763d31363041454536464142343537303146364545394544353537304438444634417e594141516c573262477777615272614241514141615a442b7a424242425678375a4e74304d4b513673513571547a416251312b7048304a4879494e5063326c7955524c53315a5a686c71585468454c6f416455706a48366345726f67596d6355755032714653445165554164654249434c4d32315252305846366c35386b7533384e584f762f664345646d6f33517a75504b4d4269396c554c5369755177757838586843525a317655684176715566306c4d6f54675a4d6e68544c747a58374f475066446463684b314d5276456e5879633262686372484f3834612f655479702f7536497371436a485541576c485666786433577278586f4d362f374b6b38687e313b207568665f7573657273746174653d414e4f4e594d4f55533b20636f756e7472795f6c616e67756167653d636e2532342533417a68253234253341636e5f7a683b206769675f63616e6172793d66616c73653b206769675f63616e6172795f7665723d31333233322d332d32373631363639353b206769675f626f6f7473747261705f345f6a707a61684d4f3443426e6c39456c6f707a667230413d6964656e746974795f766572340d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a7b2273656e736f725f64617461223a223761373447376d3233567270306f3563393335343833312e37352d312c322c2d39342c2d3130302c4d6f7a696c6c612f352e30202857696e646f7773204e5420362e333b20574f5736343b2072763a33342e3029204765636b6f2f32303130303130312046697265666f782f33342e302c7561656e642c323836372c32303130303130312c7a682d434e2c4765636b6f2c362c302c302c302c3430373730312c313634313534352c323034382c313131322c323034382c313135322c313432392c3231342c313434322c2c6370656e3a302c69313a302c646d3a302c6377656e3a302c6e6f6e3a312c6f70633a302c66633a312c73633a302c7772633a312c6973633a3135382e33393939393338393634383433382c7669623a312c6261743a302c7831313a302c7831323a312c353134332c302e3736373233353030393338332c3832383530303832303737322e352c302c6c6f633a2d312c322c2d39342c2d3133312c2d312c322c2d39342c2d3130312c646f5f656e2c646d5f656e2c745f6469732d312c322c2d39342c2d3130352c302c302c302c302c313033372c313033372c303b302c302c312c302c313037352c313337352c303b302c302c312c302c313230342c313530342c303b2d312c2d312c312c302c2d312c2d312c303b2d312c2d312c312c302c2d312c2d312c303b2d312c302c302c302c2d312c3638362c303b2d312c302c302c302c2d312c3933362c303b2d312c302c302c302c2d312c3431352c303b2d312c322c2d39342c2d3130322c302c302c302c302c313033372c313033372c303b302c302c312c302c313037352c313337352c303b302c302c312c302c313230342c313530342c303b2d312c2d312c312c302c2d312c2d312c303b2d312c2d312c312c302c2d312c2d312c303b2d312c302c302c302c2d312c3638362c303b2d312c302c302c302c2d312c3933362c303b2d312c302c302c302c2d312c3431352c303b2d312c322c2d39342c2d3130382c2d312c322c2d39342c2d3131302c2d312c322c2d39342c2d3131372c2d312c322c2d39342c2d3131312c2d312c322c2d39342c2d3130392c2d312c322c2d39342c2d3131342c2d312c322c2d39342c2d3130332c2d312c322c2d39342c2d3131322c68747470733a2f2f7777772e6968672e636f6d2e636e2f686f74656c732f636e2f7a682f7265736572766174696f6e2d312c322c2d39342c2d3131352c312c33322c33322c302c302c302c302c332c302c313635373030313634313534352c2d3939393939392c31373732362c302c302c323935342c302c302c352c302c302c45413735304445323846373531433537384145353837334531353639314643347e2d317e59414151486f7955472b45784e704f4241514141526b4c2b7a416a35544a726936364f615042374f6a53473871453954616a6d33514c365a46764776776a775952635a76435376573433576548644e6a654e3630546665664a4a49612f697461797861797446324770414532315a65313954506279697931632f526a57776e422b584b594457765371676479497757655554487a437854325572454b774748744a5955484a3061697a3364302f474a634c795672422b336136787845467335742f6947436f657850773066795954334835313853495145724b696d5939524d692f306756647a6561383862615657364d626a5a6f7445774f3748776d36353657636366626259734537644264624c4d5a4a5757754c614e4969786a2f2b6b414c685331374b72414551314f4f69676975782b4d6f4c72655361774e496e743031744e786367395a7a344a464f6c585a337a49445731433756344a4b7638315066334b415046554254584d6d335847774e434f4f706f6d7a364c736a3456584846646c6364544c7369777578495638733d7e2d317e2d317e2d312c33363930392c2d312c2d312c32353436323833322c50695a74452c33343330382c39322c302c2d312d312c322c2d39342c2d3130362c302c302d312c322c2d39342c2d3131392c2d312d312c322c2d39342c2d3132322c302c302c302c302c312c302c302d312c322c2d39342c2d3132332c2d312c322c2d39342c2d3132342c2d312c322c2d39342c2d3132362c2d312c322c2d39342c2d3132372c362d312c322c2d39342c2d37302c2d312d312c322c2d39342c2d38302c39342d312c322c2d39342c2d3131362c3132333131363434352d312c322c2d39342c2d3131382c39373731382d312c322c2d39342c2d3132392c2d312c322c2d39342c2d3132312c3b333b2d313b30227d'
        #plaintext = bytes.fromhex(s)
        self.response = Response(tls_ctx=self)
        explicit_nonce = struct.pack('!Q', self.client_seq)
        nonce = self.keystore.client_fixed_iv + explicit_nonce

        # 附加数据
        aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(plaintext))
        aes = AES_GCM()

        ciphertext, tag = aes.aes_encrypt(self.keystore.client_write_key, nonce, aead, plaintext)
        ciphertext = explicit_nonce + ciphertext + tag
        encrypted_message = b'\x17' + b'\x03\x03' + struct.pack('!H', len(ciphertext)) + ciphertext
        self.socket.send(encrypted_message)
        self.client_seq += 1
        self.plaintext_buffer_reader = []
        cache = b''

        while True:
            recv = self.socket.recv(6324)

            if not recv:
                # 服务器不保持长连接,传输完毕断开连接
                print('收到fin包')
                return

            recv = cache + recv

            cache = b''

            while recv:
                handshake_type = struct.unpack('!B', recv[:1])[0]
                length = struct.unpack('!H', recv[3:5])[0]
                flowtext = recv[5:5 + length]
                if len(flowtext) != length:
                    cache = deepcopy(recv[:])
                    break


                if handshake_type == 0x17:
                    ciphertext = flowtext

                    explicit_nonce = struct.pack('!Q', self.server_seq)
                    nonce = self.keystore.server_fixed_iv + ciphertext[:8]

                    # 附加数据
                    aead = explicit_nonce + b'\x17\x03\x03' + struct.pack('!H', len(ciphertext) - 24)
                    aes = AES_GCM()
                    # print('nonce = ',nonce)
                    # print('aead', aead)
                    explicit_nonce, ciphertext, tag = ciphertext[:8], ciphertext[8:-16], ciphertext[-16:]
                    plaintext = aes.aes_decrypt(self.keystore.server_write_key, nonce, aead, ciphertext, tag)
                    self.server_seq += 1

                    self.response.flush(plaintext)
                    if self.response.read_ended:
                        return True


                elif handshake_type == 0x15:


                    return  False

                recv = recv[5 + length:]

