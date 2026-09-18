# ============================================================
# Mini SIEM - Analyst Conclusion Test
# ============================================================

from database.db_manager import DatabaseManager


def main():

    database = DatabaseManager()

    incident_id = "INCIDENT-001"

    test_conclusion = (
        "Aynı kaynak IP adresinden web aktivitesi ve "
        "başarısız kimlik doğrulama olayları tespit edilmiştir. "
        "Olaylar korelasyon açısından incelemeye değerdir."
    )

    # Analist sonucunu kaydet
    database.save_analyst_conclusion(
        incident_id,
        test_conclusion
    )

    # Kaydedilen sonucu tekrar oku
    saved_conclusion = database.get_analyst_conclusion(
        incident_id
    )

    print("Mini SIEM Analyst Conclusion Test Sonucu")
    print("----------------------------------------")

    print(
        "Incident ID:",
        incident_id
    )

    print(
        "Analyst Conclusion:",
        saved_conclusion
    )


if __name__ == "__main__":
    main()