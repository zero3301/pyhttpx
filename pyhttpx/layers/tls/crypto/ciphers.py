
from pyhttpx.layers.tls.crypto.cipher_aead import _tls_aead_cipher_algs
from pyhttpx.layers.tls.crypto.cipher_block import _tls_block_cipher_algs


_tls_cipher_algs = {}
_tls_cipher_algs.update(_tls_block_cipher_algs)
_tls_cipher_algs.update(_tls_aead_cipher_algs)
