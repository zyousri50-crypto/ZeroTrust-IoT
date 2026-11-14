import unittest
from unittest.mock import patch

import access_control


class AccessControlResultTests(unittest.TestCase):

    @patch("access_control.get_status", return_value="Blocked")
    @patch("access_control.ovs_command")
    def test_block_returns_blocked(self, mock_ovs, mock_status):
        result = access_control.block_device("camera")
        self.assertEqual(result, "Blocked")
        self.assertEqual(mock_ovs.call_count, 2)

    @patch("access_control.get_status", return_value="Allowed")
    @patch("access_control.ovs_command")
    def test_unblock_returns_allowed(self, mock_ovs, mock_status):
        result = access_control.unblock_device("camera")
        self.assertEqual(result, "Allowed")
        self.assertEqual(mock_ovs.call_count, 2)

    @patch("access_control.get_status", return_value="Unknown")
    @patch("access_control.ovs_command")
    def test_block_detects_unexpected_result(self, mock_ovs, mock_status):
        result = access_control.block_device("camera")
        self.assertNotEqual(result, "Blocked")


if __name__ == "__main__":
    unittest.main()
