import unittest
from typing import Callable

from bt785 import CommandFrame, PacketHandler, DpData, CommandHandler, AbstractBleClient

LOCAL_KEY = '<z)o}Ezmuw01.TxQ'
LOGIN_KEY = LOCAL_KEY.encode('utf-8')[:6]
SRAND = bytes.fromhex("c4984a2a590f")


class BleClientStub(AbstractBleClient):
    def subscribe(self, callback: Callable[[bytes], None]) -> None:
        pass

    def send_data(self, data: bytes) -> None:
        print(f"BleClientStub.send_data(data={data.hex}")


class CommandFrameTest(unittest.TestCase):

    def test_parse_response(self):
        data = bytes.fromhex("0000000a000000008006000f00f00000008000740200040000028e0117030303")
        frame = CommandFrame.parse(data)
        self.assertIsNotNone(frame)
        self.assertEqual(10, frame.sn)
        self.assertEqual(0, frame.rn)
        self.assertEqual(0x8006, frame.cmd)
        self.assertEqual(15, len(frame.data))

    def test_parse_empty(self):
        frame = CommandFrame.parse(bytes())
        self.assertIsNone(frame)

    def test_invalid_crc(self):
        data = bytes.fromhex("0000000a000000008006000f00f00000008000740200040000028eFFFF030303")
        frame = CommandFrame.parse(data)
        self.assertIsNone(frame)

    def test_serialize(self):
        frame = CommandFrame(1, 2, 3, bytes([0x04]))
        packed = frame.pack()
        decoded = CommandFrame.parse(packed)
        self.assertEqual(decoded, frame)


class PacketHandlerTest(unittest.TestCase):

    def test_encrypted_packet(self):
        data = bytes.fromhex("00314b05"
                             "c6844918ad30e473232126c96d7426e6a47cf44ed9c73c4940dfb413f946ad2d"
                             "a297af5984e69474220fd2f7b0d48c01")
        bleclient = BleClientStub()
        handler = PacketHandler(bleclient, LOGIN_KEY)
        handler.set_srand(SRAND)
        handler.subscribe(self._print_decrypted)
        handler.handle_incoming_data(data)

        commandhandler = CommandHandler(handler)
        commandhandler.subscribe(self._print_incoming_cmd)

    def test_large_packet(self):
        data = bytes.fromhex("00414e05"
                             "9c4d598e66979d48bc5996235e9fd25d641daac049a5da487cd662f8c0d8f8e3"
                             "ae5b6a4c114e61dbfe223c27a599fd64a2ad17a32ec1167de6bafb55c5a38484")
        handler = PacketHandler(BleClientStub(), LOGIN_KEY)
        handler.set_srand(SRAND)
        handler.subscribe(self._print_decrypted)
        handler.handle_incoming_data(data)

    def test_device_info(self):
        data = bytes.fromhex("0081014004"
                             "1d52f7b128d913ba3020a917782539eaca2049770b82fe560d01dabc631b50af"
                             "923b56c181f99885688233cd1b13367ef00e103a914183490b29baf8b3c2a943"
                             "7010a14dfbca845e29aa365c74cd923ca2c4b3d7b66c83c372d78586d5f76475"
                             "9203c01893dee8fc0c6d1280cd0b7f521963cd6ffd1e313ab8b3853a6a6e63a9")
        ph = PacketHandler(BleClientStub(), LOGIN_KEY)
        ph.subscribe(self._print_decrypted)
        ph.handle_incoming_data(data)

    def test_command_handler(self):
        data = bytes.fromhex("0000000100000001000000600102040210015c5d9a1deaa90100c14161b10880"
                             "5adba92a221eb39d6e2f00000000000000000000000000000000000102000100"
                             "0001006266366138346d66796b756262696a3300000000000000000000000000"
                             "0000000000e76d694f23dc0095a60202")
        ph = PacketHandler(BleClientStub(), LOGIN_KEY)
        ch = CommandHandler(ph)
        ch.subscribe(self._print_incoming_cmd)
        ch.handle_incoming_packet(data)

    def _print_incoming_cmd(self, cmd: int, data: bytes):
        print(f"Incoming cmd: cmd={cmd:04X}, data={data.hex()}")

    def _print_decrypted(self, data: bytes):
        print(f"raw data = {data.hex()}")
        frame = CommandFrame.parse(data)
        print(f"command frame = {frame}")
        dpdata = DpData.parse(frame.data)
        print(f"dpdata = {dpdata}")


class DpDataTest(unittest.TestCase):

    def test_dp_data(self):
        raw = bytes.fromhex("00f00000008000740200040000028e")
        dp = DpData.parse(raw)
        print(dp)
        value = dp.intValue()
        self.assertEqual(0x74, dp.id)
        self.assertEqual(2, dp.type)
        self.assertEqual(654, dp.intValue())


if __name__ == '__main__':
    unittest.main()
