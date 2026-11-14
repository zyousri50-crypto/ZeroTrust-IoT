VALID_STATES = {"Allowed", "Denied"}


def classify_change(expected, actual, authorization=None):
    """
    Classify a service policy change.

    The authorization argument must come from a trusted
    verification mechanism, not directly from audit CSV data.
    """

    if expected not in VALID_STATES:
        return "ERROR"

    if actual not in VALID_STATES:
        return "ERROR"

    if actual == expected:
        return "COMPLIANT"

    if not isinstance(authorization, dict):
        return "VIOLATION"

    if authorization.get("verified") is not True:
        return "VIOLATION"

    if authorization.get("username") not in {
        "admin",
        "access_control_cli",
    }:
        return "VIOLATION"

    if authorization.get("result") != "Success":
        return "VIOLATION"

    action = authorization.get("action")

    if (
        action == "block"
        and expected == "Allowed"
        and actual == "Denied"
    ):
        return "AUTHORIZED_CHANGE"

    return "VIOLATION"
