# ============================================================
# Mini SIEM - MITRE ATT&CK Mapping Test
# ============================================================

from reports.mitre_attack_mapper import MitreAttackMapper


def main():

    # --------------------------------------------------------
    # TEST DETECTIONS
    #
    # Bunlar Görev 28'de test ettiğimiz detection
    # sonuçlarının örnek yapısıdır.
    # --------------------------------------------------------

    detections = [
        {
            "rule_id": "DET-001",
            "name": "Web Enumeration",
            "severity": "MEDIUM",
            "source_ip": "192.168.14.128",
            "event_ids": [10, 11, 12]
        },

        {
            "rule_id": "DET-002",
            "name": "Suspicious Web Request",
            "severity": "HIGH",
            "source_ip": "192.168.14.128",
            "event_ids": [13]
        },

        {
            "rule_id": "DET-003",
            "name":
            "Multiple Failed Authentication",

            "severity": "HIGH",

            "source_ip":
            "192.168.14.128",

            "event_ids":
            [14, 15, 16, 17, 18]
        }
    ]

    # --------------------------------------------------------
    # MITRE MAPPER
    # --------------------------------------------------------

    mapper = MitreAttackMapper()

    mappings = mapper.map_detections(
        detections
    )

    csv_path = mapper.export_csv(
        mappings
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print(
        "Mini SIEM MITRE ATT&CK Mapping Test Sonucu"
    )

    print(
        "-----------------------------------------"
    )

    print(
        "Toplam MITRE Mapping:",
        len(mappings)
    )

    print()

    for mapping in mappings:

        print(
            "Mapping ID:",
            mapping["mapping_id"]
        )

        print(
            "Detection:",
            mapping["detection_name"]
        )

        print(
            "MITRE Technique:",
            mapping["technique_id"],
            "-",
            mapping["technique_name"]
        )

        print(
            "Tactic:",
            mapping["tactic"]
        )

        print(
            "Confidence:",
            mapping["confidence"]
        )

        print(
            "Source IP:",
            mapping["source_ip"]
        )

        print(
            "Event IDs:",
            mapping["event_ids"]
        )

        print(
            "Reason:",
            mapping["reason"]
        )

        print(
            "-----------------------------------------"
        )

    print()

    print(
        "CSV MITRE Mapping:",
        csv_path
    )


if __name__ == "__main__":
    main()