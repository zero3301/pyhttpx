import struct

class TLSContext(object):
    def __init__(self, name):
        self.name = name
        self.handshake = None
        self.sequence = 0
        self.nonce = 0
        self.random = None
        self.session_id = None
        self.crypto_ctx = None
        self.finished_secret = None

class TLSSessionCtx(object):
    def __init__(self, client=True):
        self.client = client
        self.server = not self.client
        self.client_ctx = TLSContext("Client TLS context")
        self.server_ctx = TLSContext("Server TLS context")

        # packet history
        self.history = []
        self.requires_iv = False
        self.sec_params = None

class CipherMode(object):
    EAEAD = "EAEAD"


class CryptoContext(object):
    def __init__(self, tls_ctx, ctx, mode):
        self.tls_ctx = tls_ctx
        self.sec_params = self.tls_ctx.sec_params
        self.ctx = ctx
        self.mode = mode

class EAEADCryptoContext(CryptoContext):
    def __init__(self, tls_ctx, ctx):
        super(EAEADCryptoContext, self).__init__(tls_ctx, ctx, CipherMode.EAEAD)
        # Tag size is hardcoded to 128 bits in GCM for TLS
        self.tag_size = self.tls_ctx.sec_params.GCM_TAG_SIZE
        self.explicit_iv_size = self.tls_ctx.sec_params.GCM_EXPLICIT_IV_SIZE

    def __init_ciphers(self, nonce):
        self.enc_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)
        self.dec_cipher = self.sec_params.cipher_type.new(self.ctx.sym_keystore.key, mode=self.sec_params.cipher_mode,
                                                          nonce=nonce)

    def get_nonce(self, nonce=None):
        nonce = nonce or struct.pack("!Q", self.ctx.nonce)
        return b"%s%s" % (self.ctx.sym_keystore.iv, nonce)


class CryptoContextFactory(object):
    crypto_context_map = {
                          CipherMode.EAEAD: EAEADCryptoContext,
                          }
    def __init__(self, tls_ctx):
        self.tls_ctx = tls_ctx
        self.sec_params = self.tls_ctx.sec_params
        self.cipher_mode = self.sec_params.cipher_mode_name

    def new(self, ctx):
        try:
            class_ = CryptoContextFactory.crypto_context_map[self.cipher_mode]
        except KeyError:
            raise ValueError("Unavailable cipher mode: %s" % self.cipher_mode)
        return class_(self.tls_ctx, ctx)
