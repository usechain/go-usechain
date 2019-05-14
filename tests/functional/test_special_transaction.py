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

        # self.credit_contract_address = "0x63be80c1b2c777922758a7acc534423e45f81ec1"
        self.credit_contract_address = "0xfffffffffffffffffffffffffffffffff0000001"
        self.user_address_1 = "0x595d5c1f64cb173222c2b7bca914a14085ebfa52"
        # self.user_address_2 = "0xac07e0f11d98df0e20e9c8dacfdf77d904d082a7"

        unlock_payload = '{"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0x595d5c1f64cb173222c2b7bca914a14085ebfa52", "123456", 0],"id":90}'
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

        register_payload = '{"jsonrpc":"2.0","id":8245,"method":"eth_sendTransaction","params":[{"from":"%s","to":"%s","data":"0xf8161f750000000000000000000000000000000000000000000000000000000000000080222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000630783131313100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002333300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028888000000000000000000000000000000000000000000000000000000000000","value":"0x0","gas":"0x2dc6c0"}]}' % (
            self.user_address_1, self.credit_contract_address)

        print(register_payload)

        self.conn.request("POST", "/", register_payload, self.headers)
        res = self.conn.getresponse()
        data = json.loads(res.read().decode("utf-8"))

        time.sleep(6) # waiting transaction to be processed

        query_payload = '{"jsonrpc":"2.0","id":18422,"method":"eth_call","params":[{"from":"%s","to":"%s","data":"0xfd4fa05a000000000000000000000000%s","value":"0x0","gas":"0x2dc6c0"},"latest"]}' % (
            self.user_address_1, self.credit_contract_address,
            self.user_address_1[2:])
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
