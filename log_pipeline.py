# ============================================================
# Mini SIEM - Log Processing Pipeline
# ============================================================

from parsers.apache_parser import ApacheParser
from parsers.auth_parser import AuthParser
from parsers.system_parser import SystemParser

from models.normalizer import EventNormalizer
from database.db_manager import DatabaseManager


class LogPipeline:
    """
    Logların Mini SIEM içerisindeki işleme zincirini yönetir.

    Ham Log
       ↓
    Parser
       ↓
    Normalizer
       ↓
    Event
       ↓
    SQLite
    """

    def __init__(self):
        # Parser nesneleri
        self.apache_parser = ApacheParser()
        self.auth_parser = AuthParser()
        self.system_parser = SystemParser()

        # Veritabanı yöneticisi
        self.database = DatabaseManager()

    # ========================================================
    # APACHE LOG İŞLEME
    # ========================================================

    def process_apache_file(self, file_path):
        """
        Apache access.log dosyasını:
        1. Parse eder
        2. Normalize eder
        3. SQLite veritabanına kaydeder
        """

        parsed_events = self.apache_parser.parse_file(file_path)

        saved_count = 0

        for parsed_event in parsed_events:

            # Parser çıktısını ortak Event modeline çeviriyoruz.
            event = EventNormalizer.normalize_apache(parsed_event)

            # Normalize edilmiş olayı veritabanına kaydediyoruz.
            self.database.insert_event(event)

            saved_count += 1

        return saved_count

    # ========================================================
    # AUTH LOG İŞLEME
    # ========================================================

    def process_auth_file(self, file_path):
        """
        auth.log dosyasını parse eder,
        normalize eder ve SQLite'a kaydeder.
        """

        parsed_events = self.auth_parser.parse_file(file_path)

        saved_count = 0

        for parsed_event in parsed_events:

            event = EventNormalizer.normalize_auth(parsed_event)

            self.database.insert_event(event)

            saved_count += 1

        return saved_count

    # ========================================================
    # SYSTEM LOG İŞLEME
    # ========================================================

    def process_system_file(self, file_path):
        """
        syslog dosyasını parse eder,
        normalize eder ve SQLite'a kaydeder.
        """

        parsed_events = self.system_parser.parse_file(file_path)

        saved_count = 0

        for parsed_event in parsed_events:

            event = EventNormalizer.normalize_system(parsed_event)

            self.database.insert_event(event)

            saved_count += 1

        return saved_count