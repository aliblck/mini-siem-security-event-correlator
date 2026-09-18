# ============================================================
# Mini SIEM - Evidence Matrix Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from reports.evidence_matrix import EvidenceMatrixBuilder


def main():

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    database = DatabaseManager()

    rows = database.get_all_events()

    helper = CorrelationEngine()

    events = helper.database_rows_to_dicts(
        rows
    )

    # --------------------------------------------------------
    # EVIDENCE MATRIX
    # --------------------------------------------------------

    builder = EvidenceMatrixBuilder()

    matrix = builder.build(
        events
    )

    csv_path = builder.export_csv(
        matrix
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print("Mini SIEM Evidence Matrix Test Sonucu")
    print("------------------------------------")

    print(
        "Toplam Evidence:",
        len(matrix)
    )

    print()

    for item in matrix:

        print(
            "Evidence ID:",
            item["evidence_id"]
        )

        print(
            "Event ID:",
            item["event_id"]
        )

        print(
            "Timestamp:",
            item["timestamp"]
        )

        print(
            "Source:",
            item["source"]
        )

        print(
            "Source IP:",
            item["source_ip"]
        )

        print(
            "User:",
            item["user"]
        )

        print(
            "Attack Stage:",
            item["attack_stage"]
        )

        print(
            "Finding:",
            item["finding"]
        )

        print(
            "Forensic Value:",
            item["forensic_value"]
        )

        print("------------------------------------")

    print()

    print(
        "CSV Evidence Matrix:",
        csv_path
    )


if __name__ == "__main__":
    main()