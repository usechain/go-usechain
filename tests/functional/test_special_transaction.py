import unittest
import http.client
import json
import time


class TestSpecialTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.conn = http.client.HTTPConnection("127.0.0.1", 8545)
        self.headers = {
            'Content-Type': "application/json",
            'cache-control': "no-cache",
        }

        self.credit_contract_address = "UmixYUgBHA9vJj47myQKn8uZAm4an7zyYJ8"
        self.user_address_1 = "UmP5BvJrXRTwXj1EXprnJ4kLgRTTSKRd2Uc"
        self.user_address_1_Hex = "0x25df3c2c4274814aa910b1b70b06cc2c6e6a08ca"

        unlock_payload = '{"jsonrpc":"2.0","method":"personal_unlockAccount","params":["UmP5BvJrXRTwXj1EXprnJ4kLgRTTSKRd2Uc", "123456", 0],"id":90}'
        voter_start_payload = '{"jsonrpc":"2.0","method":"voter_start","params":[],"id":72}'
        miner_start_payload = '{"jsonrpc":"2.0","method":"miner_start","params":[],"id":70}'

        self.conn.request("POST", "/", unlock_payload, self.headers)
        res = self.conn.getresponse()
        data = json.loads(res.read().decode("utf-8"))

        self.conn.request("POST", "/", voter_start_payload, self.headers)
        res = self.conn.getresponse()
        data = json.loads(res.read().decode("utf-8"))

        self.conn.request("POST", "/", miner_start_payload, self.headers)
        res = self.conn.getresponse()
        data = json.loads(res.read().decode("utf-8"))
        print(data)

        time.sleep(1)

    @classmethod
    def tearDownClass(self):
        self.conn.close()

    def test_credit_register_transaction(self):

        register_payload = '{"jsonrpc":"2.0","id":8245,"method":"eth_sendTransaction","params":[{"from":"%s","to":"%s","data":"0xcd1889d800000000000000000000000000000000000000000000000000000000000000a0299bab5b4bad0a51abfe962538f951f5fbaa2691b8c7669e125d559a6b6f754000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000630783034396300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006307830303030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000043078313200000000000000000000000000000000000000000000000000000000","value":"0x0","gas":"0x2dc6c0"}]}' % (
            self.user_address_1, self.credit_contract_address)

        print(register_payload)

        self.conn.request("POST", "/", register_payload, self.headers)
        res = self.conn.getresponse()
        data = json.loads(res.read().decode("utf-8"))

        time.sleep(6) # waiting transaction to be processed

        query_payload = '{"jsonrpc":"2.0","id":18422,"method":"eth_call","params":[{"from":"%s","to":"%s","data":"0xfd4fa05a000000000000000000000000%s","value":"0x0","gas":"0x2dc6c0"},"latest"]}' % (
            self.user_address_1, self.credit_contract_address,
            self.user_address_1_Hex[2:])
        self.conn.request("POST", "/", query_payload, self.headers)
        res = self.conn.getresponse()

        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(
            data['result'],
            '0x0000000000000000000000000000000000000000000000000000000000000001'
        )
        print(data)

    # def test_upper(self):
    #     self.assertEqual('foo'.upper(), 'FOO')

    # def test_isupper(self):
    #     self.assertTrue('FOO'.isupper())
    #     self.assertFalse('Foo'.isupper())

    # def test_split(self):
    #     s = 'hello world'
    #     self.assertEqual(s.split(), ['hello', 'world'])
    #     # check that s.split fails when the separator is not a string
    #     with self.assertRaises(TypeError):
    #         s.split(2)


if __name__ == '__main__':
    unittest.main()
