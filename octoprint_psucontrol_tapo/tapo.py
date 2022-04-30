import json, time, uuid, logging
import os.path
from base64 import b64encode, b64decode
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import hashlib

log = logging.getLogger(__name__)


# API: https://k4czp3r.xyz/reverse-engineering/tp-link/tapo/2020/10/15/reverse-engineering-tp-link-tapo.html

class Device:
    def __init__(self, address: str, username: str, password: str, keypair_file: str = '/tmp/tapo.key'):
        self.session = requests.Session() # single session, stores cookie
        self.terminal_uuid = str(uuid.uuid4())
        self.address = address
        self.username = username
        self.password = password
        self.keypair_file = keypair_file
        self._create_keypair()
        self.key = None
        self.iv = None


    def _create_keypair(self):
        if self.keypair_file and os.path.exists(self.keypair_file):
            with open(self.keypair_file, 'r') as f:
                self.keypair = RSA.importKey(f.read())
        else:
            self.keypair = RSA.generate(1024)
            if self.keypair_file:
                with open(self.keypair_file, "wb") as f:
                    f.write(self.keypair.exportKey("PEM"))


    def _request_raw(self, method: str, params: dict = None):
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
        log.debug(f"Request raw: {payload}")

        # Execute call
        resp = self.session.post(url, json=payload, timeout=0.5)
        resp.raise_for_status()
        data = resp.json()

        # Check error code and get result
        if data["error_code"] != 0:
            log.error(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")

        log.debug(f"Response raw: {result}")
        return result


    def _request(self, method: str, params: dict = None):
        if not self.key:
            self._initialize()

        # Construct payload, add params if given
        payload = {
            "method": method,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid
        }
        if params:
            payload["params"] = params
        log.debug(f"Request: {payload}")

        # Encrypt payload and execute call
        encrypted = self._encrypt(json.dumps(payload))

        result = self._request_raw("securePassthrough", {"request": encrypted}) 

        # Unwrap and decrypt result
        data = json.loads(self._decrypt(result["response"]))
        if data["error_code"] != 0:
            log.error(f"Error: {data}")
            self.key = None
            raise Exception(f"Error code: {data['error_code']}")
        result = data.get("result")

        log.debug(f"Response: {result}")
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

        # Send public key and receive encrypted symmetric key
        public_key = self.keypair.publickey().exportKey("PEM").decode("UTF-8")
        public_key = public_key.replace("RSA PUBLIC KEY", "PUBLIC KEY")
        result = self._request_raw("handshake", {
            "key": public_key
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