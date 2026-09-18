# ============================================================
# Mini SIEM - Attacker Activity Reconstruction Test
# ============================================================

from database.db_manager import DatabaseManager
from detection.correlation import CorrelationEngine
from detection.attacker_reconstruction import AttackerReconstructor


def main():

    # --------------------------------------------------------
    # VERİTABANINDAN EVENTLERİ AL
    # --------------------------------------------------------

    database = DatabaseManager()

    rows = database.get_all_events()

    helper = CorrelationEngine()

    events = helper.database_rows_to_dicts(
        rows
    )

    # --------------------------------------------------------
    # RECONSTRUCTION
    # --------------------------------------------------------

    reconstructor = AttackerReconstructor()

    result = reconstructor.reconstruct(
        events
    )

    # --------------------------------------------------------
    # SONUÇ
    # --------------------------------------------------------

    print(
        "Mini SIEM Attacker Activity Reconstruction"
    )

    print(
        "------------------------------------------"
    )

    print(
        "First Seen:",
        result["first_seen"]
    )

    print(
        "Last Seen:",
        result["last_seen"]
    )

    print(
        "Source IP:",
        result["source_ips"]
    )

    print(
        "Users:",
        result["users"]
    )

    print()

    print("Attack Timeline:")

    print(
        "------------------------------------------"
    )

    for number, item in enumerate(
        result["timeline"],
        start=1
    ):

        print(
            f"{number}. {item['timestamp']}"
        )

        print(
            "   Stage:",
            item["stage"]
        )

        print(
            "   Source:",
            item["source"]
        )

        print(
            "   Source IP:",
            item["source_ip"]
        )

        print(
            "   User:",
            item["user"]
        )

        print(
            "   Status:",
            item["status"]
        )

        if item["url"]:

            print(
                "   URL:",
                item["url"]
            )

        print(
            "------------------------------------------"
        )

    print()

    print("Stage Summary:")

    for stage, count in result[
        "stage_counts"
    ].items():

        print(
            f"- {stage}: {count}"
        )


if __name__ == "__main__":
    main()