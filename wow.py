import pyDH
from hashlib import sha256
def diffieHellmanKeyExchangeCalculations(serverDHPublicKey):
    # Generating session key
    sessionKey = pyDH.DiffieHellman(5).gen_shared_key(serverDHPublicKey)
    print("SESS")
    print(sessionKey)
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = sha256(sessionKey.encode()).digest()
    # Returning the value of AES Session Key
    return AESSessionKey
wow1 = pyDH.DiffieHellman(5)
wow2 = pyDH.DiffieHellman(5)
ses1 = pyDH.DiffieHellman(5).gen_shared_key(wow1)
ses2 = pyDH.DiffieHellman(5).gen_shared_key(wow2)
print(ses1)
print(ses2)

import pyDH
d1 = pyDH.DiffieHellman(5)
d2 = pyDH.DiffieHellman(5)
d1_pubkey = d1.gen_public_key()
d2_pubkey = d2.gen_public_key()
d1_sharedkey = d1.gen_shared_key(d2_pubkey)
d2_sharedkey = d2.gen_shared_key(d1_pubkey)
print(d1_sharedkey == d2_sharedkey)
