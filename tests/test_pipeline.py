# ============================================================
# Mini SIEM - Log Pipeline Test
# ============================================================

from pathlib import Path

from log_pipeline import LogPipeline


# Projenin ana klasörünü buluyoruz.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# sample_logs klasörünün yolunu oluşturuyoruz.
SAMPLE_LOGS = PROJECT_ROOT / "sample_logs"


def main():

    # Mini SIEM log işleme zincirini başlatıyoruz.
    pipeline = LogPipeline()

    # Apache logunu işler.
    apache_count = pipeline.process_apache_file(
        SAMPLE_LOGS / "apache_sample.log"
    )

    # Auth logunu işler.
    auth_count = pipeline.process_auth_file(
        SAMPLE_LOGS / "auth_sample.log"
    )

    # System logunu işler.
    system_count = pipeline.process_system_file(
        SAMPLE_LOGS / "system_sample.log"
    )

    print("Mini SIEM Pipeline Test Sonucu")
    print("--------------------------------")

    print("Apache Event Sayısı:", apache_count)
    print("Auth Event Sayısı:", auth_count)
    print("System Event Sayısı:", system_count)

    print(
        "Toplam Veritabanı Event Sayısı:",
        pipeline.database.get_event_count()
    )

    print("\nVeritabanındaki Eventler:")

    for event in pipeline.database.get_all_events():
        print(event)


if __name__ == "__main__":
    main()