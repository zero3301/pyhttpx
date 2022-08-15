
from __future__ import with_statement
from __future__ import print_function

import hashlib,hmac

def _prf(secret, seed,hashes, numblocks):
    output = b''

    def A(seed):
        while 1:
            seed = hmac.new(secret, seed, hashes).digest()
            yield seed

    a = A(seed)
    for j in range(numblocks):
        output += hmac.new(secret, msg=next(a) + seed, digestmod=hashes).digest()

    return output

def prf(pms, seed,hashes=None,step=10,outlen=48):
    #每一步多加32byte
    out = _prf(pms, seed, hashes,step)
    return out[:outlen]



def export_master_secret(pre_master_secret,client_random,server_random):
    seed = b'master secret' + client_random + server_random
    hashes = hashlib.sha384
    ms = prf(pre_master_secret, seed,hashes, outlen=48)
    return ms

def export_key_block(master_secret,server_random,client_random):
    seed = b'key expansion' + server_random + client_random
    hashes = hashlib.sha384
    key_block = prf(master_secret, seed,hashes, outlen=256)
    return key_block
if __name__ == '__main__':


    pre_master_secret =b'\x97$\xe0K\x15_\x8baQ\xdc\xd1\x83a\xf8\x8eq~R5\x04\xbb\xe8y\xe2\xbe,\xf13\x92\xab\xf0\xf6'

    client_random=  bytes.fromhex('09f9a3e83dc9f885b3fe36c8b6b6de942274bf5109c2bfb9f1396b8ab637bb0d')
    server_random= bytes.fromhex('07adfe6f6dcda1cd84fc2d7dd50f197f638c6d47d489f2971253c479a3a4c552')



    s='4115d6397d8f9f39bf008f7ed900b236bf3ba8e579bb46332dc420f54da41bb99ef157b672b1fa2a26992c84c02a1cf1'
    master = bytes.fromhex(s)

    key_block = export_key_block(master,server_random,client_random)

    client_write_key = key_block[:32]
    server_write_key = key_block[32:64]
    client_write_iv = key_block[64:76]

    print(client_write_key)
    print(client_write_iv)






