# ============================================================
# Mini SIEM - Incident Response Test
# ============================================================

from detection.incident_response import IncidentResponseEngine


def main():

    # --------------------------------------------------------
    # TEST INCIDENT
    # --------------------------------------------------------

    incident = {
        "incident_id": "INCIDENT-001",
        "severity": "CRITICAL",
        "source_ips": [
            "192.168.14.128"
        ]
    }

    # Daha önce oluşturduğumuz detection sonuçlarının
    # örnek yapısı.
    detections = [
        {
            "rule_id": "DET-001",
            "name": "Web Enumeration",
            "severity": "MEDIUM"
        },
        {
            "rule_id": "DET-002",
            "name": "Suspicious Web Request",
            "severity": "HIGH"
        },
        {
            "rule_id": "DET-003",
            "name": "Multiple Failed Authentication",
            "severity": "HIGH"
        }
    ]

    correlations = [
        {
            "rule_id": "CORR-001",
            "name":
            "Web Activity → Failed Authentication"
        }
    ]

    # --------------------------------------------------------
    # RESPONSE ENGINE
    # --------------------------------------------------------

    engine = IncidentResponseEngine()

    response = engine.generate_response(
        incident=incident,
        detections=detections,
        correlations=correlations
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Incident Response Test Sonucu")
    print("---------------------------------------")

    print(
        "Incident ID:",
        response["incident_id"]
    )

    print(
        "Severity:",
        response["severity"]
    )

    print(
        "Source IP:",
        response["source_ips"]
    )

    print(
        "Response Action Sayısı:",
        response["action_count"]
    )

    print()

    for number, action in enumerate(
        response["actions"],
        start=1
    ):

        print(
            f"{number}. Phase:",
            action["phase"]
        )

        print(
            "Priority:",
            action["priority"]
        )

        print(
            "Action:",
            action["action"]
        )

        print("---------------------------------------")


if __name__ == "__main__":
    main()