import unittest

from verification_policy import classify_change


class AuthorizationSecurityTests(unittest.TestCase):

    def test_missing_verification(self):
        authorization = {
            "username": "admin",
            "action": "block",
            "result": "Success",
        }
        self.assertEqual(
            classify_change("Allowed", "Denied", authorization),
            "VIOLATION",
        )

    def test_false_verification(self):
        authorization = {
            "verified": False,
            "username": "admin",
            "action": "block",
            "result": "Success",
        }
        self.assertEqual(
            classify_change("Allowed", "Denied", authorization),
            "VIOLATION",
        )

    def test_wrong_admin(self):
        authorization = {
            "verified": True,
            "username": "attacker",
            "action": "block",
            "result": "Success",
        }
        self.assertEqual(
            classify_change("Allowed", "Denied", authorization),
            "VIOLATION",
        )

    def test_block_cannot_authorize_unexpected_allow(self):
        authorization = {
            "verified": True,
            "username": "admin",
            "action": "block",
            "result": "Success",
        }
        self.assertEqual(
            classify_change("Denied", "Allowed", authorization),
            "VIOLATION",
        )


if __name__ == "__main__":
    unittest.main()
