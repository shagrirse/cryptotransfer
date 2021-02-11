import os
files = os.listdir(os.path.dirname(os.path.join(os.path.dirname(__file__), f"database/")))
print(files)