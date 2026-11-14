import unittest

from verification_policy import classify_change


class VerificationPolicyTests(unittest.TestCase):

    def test_compliant(self):
        result = classify_change(
            expected="Allowed",
            actual="Allowed",
            authorization=None,
        )
        self.assertEqual(result, "COMPLIANT")

    def test_authorized_block(self):
        result = classify_change(
            expected="Allowed",
            actual="Denied",
            authorization={
                "action": "block",
                "username": "admin",
                "result": "Success",
                "verified": True,
            },
        )
        self.assertEqual(result, "AUTHORIZED_CHANGE")

    def test_unverified_block(self):
        result = classify_change(
            expected="Allowed",
            actual="Denied",
            authorization=None,
        )
        self.assertEqual(result, "VIOLATION")

    def test_unblock_does_not_authorize_block(self):
        result = classify_change(
            expected="Allowed",
            actual="Denied",
            authorization={
                "action": "unblock",
                "username": "admin",
                "result": "Success",
                "verified": True,
            },
        )
        self.assertEqual(result, "VIOLATION")


if __name__ == "__main__":
    unittest.main()
