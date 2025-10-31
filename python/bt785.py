#!/usr/bin/env python3
import argparse
import asyncio
import secrets
import struct
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from hashlib import md5
from struct import pack, unpack
from typing import Callable, List
from typing import override

from Crypto.Cipher import AES
from bleak import BleakClient, BleakGATTCharacteristic


# interface for BLE layer
class AbstractBleClient(ABC):
    @abstractmethod
    def send_data(self, data: bytes) -> None:
        pass

    @abstractmethod
    def subscribe(self, subscriber: Callable[[bytes], None]) -> None:
        pass


@dataclass
class EncryptedPacket:
    security_flag: int
    iv: bytes
    encrypted: bytes

    def pack(self) -> bytes:
        b = bytearray()
        b += self.security_flag.to_bytes(1)
        b += self.iv
        b += self.encrypted
        return bytes(b)

    @classmethod
    def parse(cls, rawbytes: bytes):
        if len(rawbytes) < 17:
            return None
        flag = rawbytes[0]
        iv = rawbytes[1:17]
        encrypted = rawbytes[17:]
        return cls(flag, iv, encrypted)


class AbstractPacketHandler(ABC):
    def __init__(self, login_key: bytes):
        self.login_key = login_key
        self.keys = {4: md5(login_key).digest()}

    def set_key1(self, key1: bytes) -> None:
        self.keys[1] = key1

    def set_srand(self, srand: bytes) -> None:
        self.keys[5] = md5(self.login_key + srand).digest()

    def _find_key(self, security_flag) -> bytes | None:
        return self.keys.get(security_flag)

    @abstractmethod
    def subscribe(self, subscriber: Callable[[bytes], None]) -> None:
        pass

    @abstractmethod
    def send_packet(self, security_flag: int, data: bytes) -> bool:
        pass


class PacketHandler(AbstractPacketHandler):
    def __init__(self, bleclient: AbstractBleClient, login_key: bytes):
        super().__init__(login_key)
        self.bleclient = bleclient
        self.protocol_version = 2
        self.subscribers = []
        self.bleclient.subscribe(self.handle_incoming_data)

    @override
    def subscribe(self, subscriber: Callable[[bytes], None]) -> None:
        self.subscribers.append(subscriber)

    @staticmethod
    def _decode_varint(data: bytes, offset=0):
        shift = 0
        result = 0
        while True:
            b = data[offset]
            offset += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, offset

    def handle_incoming_data(self, data: bytes) -> None:
        # parse fragmentation layer
        packetnr = data[0]
        if packetnr != 0:
            print(f"expected packet 0, got {packetnr}")
            return
        length, offset = self._decode_varint(data, 1)
        offset += 1  # skip flag/version
        encrypted_raw = data[offset:]

        # parse encryption layer
        encrypted = EncryptedPacket.parse(encrypted_raw)
        if not encrypted:
            print(f"Could not parse encrypted fragment: {encrypted_raw.hex()}")
            return

        # decrypt and notify
        decrypted = self._decrypt(encrypted)
        if decrypted:
            for subcriber in self.subscribers:
                subcriber(decrypted)

    @override
    def send_packet(self, security_flag: int, data: bytes) -> bool:
        key = self._find_key(security_flag)
        if not key:
            return False

        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = (-len(data)) % 16
        padded = data + bytes([pad_len]) * pad_len
        padded = cipher.encrypt(padded)

        encrypted = EncryptedPacket(security_flag, iv, padded)
        buffer = encrypted.pack()

        self._send_fragments(buffer)
        return True

    def _decrypt(self, encrypted: EncryptedPacket) -> bytes | None:
        key = self._find_key(encrypted.security_flag)
        if not key:
            return None
        cipher = AES.new(key, AES.MODE_CBC, encrypted.iv)
        return bytes(cipher.decrypt(encrypted.encrypted))

    def _send_fragments(self, data) -> None:
        packet_nr = 0
        maxsize = 23
        b = bytearray()
        b += pack("BBB", packet_nr, len(data), self.protocol_version << 4)
        for d in data:
            if len(b) % maxsize == 0:
                self._send_one_fragment(b)
                packet_nr += 1
                b = bytearray([packet_nr])
            b += d.to_bytes(1)
        if len(b) > 1:
            self._send_one_fragment(b)

    def _send_one_fragment(self, data):
        self.bleclient.send_data(data)


@dataclass
class CommandFrame:
    sn: int  # serial number
    rn: int  # reference number
    cmd: int
    data: bytes

    def pack(self) -> bytes:
        b = bytearray()
        b += pack(">IIHH", self.sn, self.rn, self.cmd, len(self.data))
        b += self.data
        crc = self._crc16(b)
        return b + pack('>H', crc)

    def __repr__(self):
        return f"CommandFrame(sn={self.sn},rn={self.rn},cmd=0x{self.cmd:04X},data=<{len(self.data)}bytes>)"

    @staticmethod
    def _crc16(data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 255
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001
        return crc

    @classmethod
    def parse(cls, rawbytes):
        if len(rawbytes) < 14:
            return None
        sn, rn, cmd, length = unpack(">IIHH", rawbytes[:12])
        offset = 12
        if offset + length + 2 > len(rawbytes):
            print(f"buffer too small ({rawbytes.hex()}) / length too big ({length})")
            return None
        data = bytes(rawbytes[offset: offset + length])
        offset += length
        crc = unpack(">H", rawbytes[offset:offset + 2])[0]
        actual = cls._crc16(rawbytes[:offset])
        offset += 2
        if actual != crc:
            print(f"CRC mismatch, frame {crc:02X}, actual {actual:02X}")
            return None
        return cls(sn, rn, cmd, data)

    def matches_command(self, command) -> bool:
        return command and self.cmd == command.cmd and self.rn == command.sn


@dataclass
class DeviceInfo:
    srand: bytes
    key1: bytes
    devid: bytes
    mac: bytes

    @classmethod
    def parse(cls, data: bytes):
        srand = data[6:12]
        key1 = data[14:30]
        devid = data[55:71]
        mac = data[89:95][::-1]
        return cls(srand, key1, devid, mac)


class CommandHandler:
    PROTOCOL_VERSION = 2

    CMD_DEVICE_INFO = 0
    CMD_PAIR = 1

    def __init__(self, packet_handler: AbstractPacketHandler):
        self.packet_handler = packet_handler
        self._sn = 0
        # command/response handling
        self.event = None
        self.active_command = None
        self.active_response = None
        # subscriptions
        self._subscribers = []
        self.packet_handler.subscribe(self.handle_incoming_packet)

    def subscribe(self, subscriber: Callable[[int, bytes], None]) -> None:
        self._subscribers.append(subscriber)

    def handle_incoming_packet(self, data: bytes) -> None:
        frame = CommandFrame.parse(data)
        if frame:
            # our own command/response processing
            if frame.matches_command(self.active_command):
                self.active_response = frame
                self.event.set()
            else:
                # notify our subscribers
                for subscriber in self._subscribers:
                    subscriber(frame.cmd, frame.data)

    def _get_sn(self) -> int:
        self._sn += 1
        return self._sn

    def request_device_info(self) -> DeviceInfo | None:
        # build command packet
        frame = CommandFrame(self._get_sn(), 0, self.CMD_DEVICE_INFO, bytes([0, 0xF3]))
        response = self._exchange_command(4, frame)
        if response:
            device_info = DeviceInfo.parse(response.data)
            if device_info:
                self.packet_handler.set_key1(device_info.key1)
                self.packet_handler.set_srand(device_info.srand)
            return device_info
        return None

    def pair(self, uuid: str, loginkey: bytes, devid: bytes) -> int | None:
        pair_data = uuid.encode('utf-8') + loginkey + devid
        frame = CommandFrame(self._get_sn(), 0, self.CMD_PAIR, pair_data)
        response = self._exchange_command(5, frame)
        return int.from_bytes(response.data) if response else None

    def _exchange_command(self, security_flag: int, command: CommandFrame, timeout: float = 1) -> CommandFrame | None:
        # send it
        data = command.pack()
        self.event = threading.Event()
        self.active_command = command
        self.active_response = None
        self.packet_handler.send_packet(security_flag, data)

        # wait for response
        self.event.wait(timeout)
        self.active_command = None
        return self.active_response


class DpType(Enum):
    TEMPERATURE_C = (0x08, 2, "Temperature", 0.1, "degC")
    TEMPERATURE_F = (0x6A, 2, "Temperature", 0.1, "degF")
    TDS = (0x6F, 2, "TDS", 1, "ppm")
    EC = (0x74, 2, "EC", 1, "us/cm")
    SALT_PPM = (0x79, 2, "Salt", 1, "ppm")
    SALT_SG = (0x7E, 2, "SG", 0.001, "kg/l")

    def __init__(self, dpid: int, dptype: int, description: str, scale: float, unit: str):
        self.dpid = dpid
        self.dptype = dptype
        self.description = description
        self.scale = scale
        self.unit = unit

    @classmethod
    def from_code(cls, dpid: int):
        for member in cls:
            if member.dpid == dpid:
                return member
        return None


@dataclass
class DpData:
    dp_id: int
    dp_type: int
    data: bytes

    @classmethod
    def parse(cls, raw: bytes):
        if len(raw) < 12:
            return None
        dpid, dptype, length = struct.unpack(">BBH", raw[7:11])
        data = raw[11:]
        return cls(dpid, dptype, data)

    def int_value(self) -> int:
        return struct.unpack(">I", self.data)[0]

    def __repr__(self):
        dptype = DpType.from_code(self.dp_id)
        if dptype:
            value = round(dptype.scale * self.int_value(), 3)
            return f"{dptype.dpid}: {dptype.description}={value} {dptype.unit}"
        return f"DpData(id={self.dp_id},type={self.dp_type},data={self.data.hex()})"


class BleakBleClient(AbstractBleClient):
    def __init__(self, address: str, write_char: str, notify_char: str):
        self.address: str = address
        self.write_char: str = write_char
        self.notify_char: str = notify_char
        self.subscribers: List[Callable[[bytes], None]] = []

        # Each client instance has its own event loop thread
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

        self.client: BleakClient = BleakClient(address)

    def _run(self, coro):
        """Run a coroutine safely in the background event loop thread."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result()

    def connect(self) -> None:
        print(f"Connecting to BLE device {self.address}...")
        self._run(self.client.connect())
        if not self.client.is_connected:
            raise RuntimeError("Failed to connect to BLE device")
        print("Connected successfully!")
        self._run(self.client.start_notify(self.notify_char, self._notify_callback))

    def disconnect(self) -> None:
        try:
            if self.client.is_connected:
                print("Disconnecting...")
                self._run(self.client.disconnect())
        except Exception as e:
            print(f"Error during disconnect: {e}")
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self._thread.join(timeout=2)

    def is_connected(self) -> bool:
        return self.client.is_connected

    def send_data(self, data: bytes) -> None:
        if not self.client.is_connected:
            print("Cannot send data — not connected.")
            return
        print(f"BLE sending: {data.hex()}")
        self._run(self.client.write_gatt_char(self.write_char, data))

    def _notify_callback(self, _characteristic: BleakGATTCharacteristic, data: bytearray) -> None:
        b = bytes(data)
        for subscriber in self.subscribers:
            subscriber(b)

    def subscribe(self, subscriber: Callable[[bytes], None]) -> None:
        self.subscribers.append(subscriber)


def _handle_frame(cmd: int, data: bytes) -> None:
    if cmd == 0x8006:
        dpdata = DpData.parse(data)
        if dpdata:
            print(f"dpdata = {dpdata}")
    else:
        print(f"Unhandled command {cmd:04x}: {data.hex()}")


WRITE_CHAR = "00000001-0000-1001-8001-00805f9b07d0"
NOTIFY_CHAR = "00000002-0000-1001-8001-00805f9b07d0"


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--device", help="The BT785 bluetooth address", default="DC:23:4F:69:6D:E7")
    parser.add_argument("-u", "--uuid", help="The BT785 16-character uuid", default="ebc1a468b06623eb")
    parser.add_argument("-k", "--key", help="The BT785 local key", default="<z)o}Ezmuw01.TxQ")
    args = parser.parse_args()

    login_key = args.key.encode()[:6]
    reconnect_delay = 5  # seconds

    while True:
        bleclient = None
        try:
            bleclient = BleakBleClient(args.device, WRITE_CHAR, NOTIFY_CHAR)
            ph = PacketHandler(bleclient, login_key)
            ch = CommandHandler(ph)
            ch.subscribe(_handle_frame)
            bleclient.connect()

            device_info = ch.request_device_info()
            print(f"device_info = {device_info}")
            if device_info:
                pair_result = ch.pair(args.uuid, login_key, device_info.devid)
                print(f"pair result = {pair_result}")

            print("Connected and initialized. Monitoring...")
            while bleclient.is_connected():
                time.sleep(1)

            print("Connection lost, will attempt reconnect...")
            time.sleep(reconnect_delay)

        except KeyboardInterrupt:
            print("Exiting...")
            if bleclient:
                bleclient.disconnect()
            break

        except Exception as e:
            print(f"Error: {e}")
            if bleclient:
                bleclient.disconnect()
            print(f"Retrying in {reconnect_delay}s...")
            time.sleep(reconnect_delay)


if __name__ == "__main__":
    main()
