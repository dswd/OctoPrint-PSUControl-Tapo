import json, time, uuid, logging
from base64 import b64encode, b64decode
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import hashlib

log = logging.getLogger(__name__)


class Device:
    def __init__(self, address: str, username: str, password: str, keypair=None):
        self.session = requests.Session() # single session, stores cookie
        self.terminal_uuid = str(uuid.uuid4())
        self.address = address
        self.username = username
        self.password = password
        self.keypair = keypair or RSA.generate(1024)
        self.key = None
        self.iv = None
        self.initializing = False


    def _request(self, method: str, params: dict = None):
        # Initialize if not done yet
        if not self.initializing and (not self.key or not self.token):
            self._initialize()

        # Construct url, add token if we have one
        url = f"http://{self.address}/app"
        if self.token:
            url += f"?token={self.token}"

        # Construct payload, add params if given
        payload = {
            "method": method,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid
        }
        if params:
            payload["params"] = params
        log.info("REQUEST:", payload)

        # If we have a key, encrypt payload and wrap in securePassthrough request
        if self.key:
            encrypted = self._encrypt(json.dumps(payload))
            payload = {
                "method": "securePassthrough",
                "params": {
                    "request": encrypted
                }
            }

        # Execute call
        resp = self.session.post(url, json=payload, timeout=2)
        resp.raise_for_status()
        data = resp.json()

        # Check error code and get result
        if data["error_code"] != 0:
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")

        # If we used securePassthrough, unwrap and decrypt result
        if self.key:
            data = json.loads(self._decrypt(result["response"]))
            if data["error_code"] != 0:
                raise Exception(f"Error code: {data['error_code']}")
            result = data.get("result")

        log.info("RESPONSE:", repr(result))
        return result


    def _encrypt(self, data: str):
        data = data.encode("UTF-8")

        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16) 
        data = data + bytes([pad_l] * pad_l)

        # Encrypt data with key
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        data = crypto.encrypt(data)

        # Base64 encode
        data = b64encode(data).decode("UTF-8")
        return data


    def _decrypt(self, data: str):
        # Base64 decode data
        data = b64decode(data.encode("UTF-8"))

        # Decrypt data with key
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv)
        data = crypto.decrypt(data)

        # Remove PKCS#7 padding
        data = data[:-data[-1]] 
        return data.decode("UTF-8")


    def _initialize(self):
        # Unset key and token
        self.key = None
        self.token = None
        self.initializing = True

        # Send public key and receive encrypted symmetric key
        result = self._request("handshake", {
            "key": self.keypair.publickey().exportKey("PEM").decode("UTF-8")
        })
        encrypted = b64decode(result["key"].encode("UTF-8"))
        
        # Decrypt symmetric key
        cipher = PKCS1_v1_5.new(self.keypair)
        decrypted = cipher.decrypt(encrypted, None)
        self.key, self.iv = decrypted[:16], decrypted[16:]

        # Base64 encode password and hashed username
        digest = hashlib.sha1(self.username.encode("UTF-8")).hexdigest()
        username = b64encode(digest.encode("UTF-8")).decode("UTF-8")
        password = b64encode(self.password.encode("UTF-8")).decode("UTF-8")

        # Send login info and receive session token
        result = self._request("login_device", {
            "username": username,
            "password": password
        })
        self.token = result["token"]
        self.initializing = False


    def _get_device_info(self):
        return self._request("get_device_info")


    def _set_device_info(self, params: dict):
        return self._request("set_device_info", params)        


class P100(Device):
    def get_status(self) -> bool:
        return self._get_device_info()["device_on"]

    def set_status(self, status: bool):
        return self._set_device_info({"device_on": status})