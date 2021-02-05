from Cryptodome.PublicKey import RSA
def ServerRSAPrivateKeygenerate():
    # Generate 2048-bit long RSA Key pair
    ServerRSAkey = RSA.generate(2048)
    # Make RSA key generated a private key
    ServerPrivateRSAKey = ServerRSAkey
    # Return RSA key
    return ServerPrivateRSAKey.export_key()
print(ServerRSAPrivateKeygenerate())