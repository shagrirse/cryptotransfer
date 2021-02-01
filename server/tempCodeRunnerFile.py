from Cryptodome.Random import get_random_bytes

non = get_random_bytes(12)
print(non)
print(non[-10:])