import scim_server_sigsci
import unittest
import json


class TestServer(unittest.TestCase):

    def setUp(self):
        self.app = scim_server_sigsci.app.test_client()
        self.app.testing = True

    def test_status_code(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 401)

    def test_message(self):
        response = self.app.get('/')
        jsonData = response.json
        statusMsg = int(jsonData["status"])
        self.assertEqual(response.status_code, statusMsg)

if __name__ == '__main__':
    unittest.main()