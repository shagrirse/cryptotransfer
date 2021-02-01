# A function that performs Diffle-Hellman Key Exchange Calculations
def diffieHellmanKeyExchangeCalculations(serverDHPublicKey):
    # Calculating session key
    sessionKey = (serverDHPublicKey**a) % p
    # Hashing the session key to be a AES 256-bit session key
    AESSessionKey = hashlib.sha256(sessionKey.encode()).hexdigest()
    # Returning the value of AES Session Key
    return AESSessionKey


# A function that performs AES Encryption Operation
def AESOperation():
    with open("day_end.csv", "rb") as f:
        # Extracting data in bytes
        unencryptedData = f.read()
        # Generating AES IV
        AESIV = get_random_bytes(16)
        # Instantiating AES cipher
        AESCipher = AES.new(diffieHellmanKeyExchangeCalculations(
            serverDHPublicKey), AES.MODE_CTR, AESIV)
        # AES block size is 128 bits or 16 bytes
        AESEncryptedData = AESCipher.encrypt(
            pad(unencryptedData, AES.block_size))
        # Returning ASES Encrypted Data in bytes
        return AESEncryptedData