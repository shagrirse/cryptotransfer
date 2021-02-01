from Cryptodome.Random import get_random_bytes

non = get_random_bytes(12)
print(non)
wow = non[-10:]
print(non - wow)