import json, time, uuid, logging
import os.path
import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA1
from Crypto.Random import get_random_bytes
import hashlib

log = logging.getLogger(__name__)

def sha1(data: bytes) -> bytes:
    return SHA1.new(data).digest()

def sha256(data: bytes) -> bytes:
    return SHA256.new(data).digest()

def calc_auth_hash(username: str, password: str) -> bytes:
    return sha256(sha1(username.encode()) + sha1(password.encode()))

class Device:
    def __init__(self, address: str, username: str, password: str, keypair_file: str = '/tmp/tapo.key'):
        self.session = requests.Session() # single session, stores cookie
        self.terminal_uuid = str(uuid.uuid4())
        self.address = address
        self.username = username
        self.password = password
        self.key = None
        self.iv = None
        self.seq = None
        self.sig = None

    def _request_raw(self, path: str, data: bytes, params: dict = None):
        url = f"http://{self.address}/app/{path}"
        resp = self.session.post(url, data=data, timeout=0.5, params=params)
        resp.raise_for_status()
        data = resp.content
        return data

    def _request(self, method: str, params: dict = None):
        if not self.key:
            self._initialize()
        payload = {
            "method": method
        }
        if params:
            payload["params"] = params
        log.debug(f"Request: {payload}")
        # Encrypt payload and execute call
        encrypted = self._encrypt(json.dumps(payload).encode("UTF-8"))
        result = self._request_raw("request", encrypted, params={"seq": self.seq}) 
        # Unwrap and decrypt result
        data = json.loads(self._decrypt(result).decode("UTF-8"))
        log.debug(f"Response: {data}")
        return data.get("result")

    def _encrypt(self, data: bytes):
        self.seq += 1
        seq = self.seq.to_bytes(4, "big", signed=True)
        # Add PKCS#7 padding
        pad_l = 16 - (len(data) % 16) 
        data = data + bytes([pad_l] * pad_l)
        # Encrypt data with key
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv + seq)
        ciphertext = crypto.encrypt(data)
        # Signature
        sig = sha256(self.sig + seq + ciphertext)
        return sig + ciphertext

    def _decrypt(self, data: bytes):
        # Decrypt data with key
        seq = self.seq.to_bytes(4, "big", signed=True)
        crypto = AES.new(self.key, AES.MODE_CBC, self.iv + seq)
        data = crypto.decrypt(data[32:])

        # Remove PKCS#7 padding
        data = data[:-data[-1]] 
        return data

    def _initialize(self):
        local_seed = get_random_bytes(16)
        response = self._request_raw("handshake1", local_seed)
        remote_seed, server_hash = response[0:16], response[16:]
        auth_hash = None
        for creds in [(self.username, self.password), ("", ""), ("kasa@tp-link.net", "kasaSetup")]:
            ah = calc_auth_hash(*creds)
            local_seed_auth_hash = sha256(local_seed + remote_seed + ah)
            if local_seed_auth_hash == server_hash: 
                auth_hash = ah
                log.debug(f"Authenticated with {creds[0]}")
                break
        if not auth_hash:
            raise Exception("Failed to authenticate")
        self._request_raw("handshake2", sha256(remote_seed + local_seed + auth_hash))
        self.key = sha256(b"lsk" + local_seed + remote_seed + auth_hash)[:16]
        ivseq = sha256(b"iv" + local_seed + remote_seed + auth_hash)
        self.iv = ivseq[:12]
        self.seq = int.from_bytes(ivseq[-4:], "big", signed=True)
        self.sig = sha256(b"ldk" + local_seed + remote_seed + auth_hash)[:28]
        log.debug(f"Initialized")
    
    def _get_device_info(self):
        return self._request("get_device_info")

    def _set_device_info(self, params: dict):
        return self._request("set_device_info", params)        

    def get_type(self) -> str:
        return self._get_device_info()["model"]

    def get_model(self) -> str:
        return self._get_device_info()["type"]


class Switchable(Device):
    def get_status(self) -> bool:
        return self._get_device_info()["device_on"]

    def get_on_time(self) -> int:
        return self._get_device_info()["on_time"]

    def set_status(self, status: bool):
        return self._set_device_info({"device_on": status})

    def turn_on(self):
        return self.set_status(True)

    def turn_off(self):
        return self.set_status(False)

    def toggle(self):
        return self.set_status(not self.get_status())


class Metering(Device):
    def get_energy_usage(self) -> dict:
        return self._request("get_energy_usage")


class Dimmable(Device):
    # Set brightness level (0-100)
    def set_brightness(self, brightness: int):
        return self._set_device_info({"brightness": brightness})

class ColorTemp(Device):
    # Set color temperature in Kelvin
    def set_color_temp(self, color_temp: int):
        return self._set_device_info({"color_temp": color_temp})

class ColorRGB(Device):
    def set_color_rgb(self, hue, saturation):
        return self._set_device_info({"color_temp": 0, "hue": hue, "saturation": saturation})



class P100(Switchable): pass
class P110(Switchable, Metering): pass
class L520(Switchable, Dimmable): pass
class L510(Switchable, Dimmable, ColorTemp): pass
class L530(Switchable, Dimmable, ColorTemp, ColorRGB): pass
class L900(Switchable, Dimmable, ColorTemp, ColorRGB): pass
class L920(Switchable, Dimmable, ColorTemp, ColorRGB): pass
