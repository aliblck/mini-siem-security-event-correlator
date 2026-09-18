# ============================================================
# Mini SIEM - Correlation Engine
# Olay İlişkilendirme Motoru
# ============================================================

from datetime import datetime
import re


class CorrelationEngine:
    """
    Mini SIEM Correlation Engine.

    Farklı log kaynaklarından gelen olayların:

    - Source IP
    - User
    - Process
    - Timestamp
    - Event Type

    alanlarını karşılaştırarak ilişkili olayları tespit eder.

    Önemli:
    Korelasyon, iki olay arasında kesin nedensellik olduğunu
    kanıtlamaz. Sadece olaylar arasında anlamlı bir ilişki
    bulunduğunu gösterir.
    """

    # Veritabanındaki events tablosunun sütun sırası.
    EVENT_COLUMNS = [
        "id",
        "timestamp",
        "source",
        "source_ip",
        "destination_ip",
        "user",
        "process",
        "event_type",
        "action",
        "status",
        "message",
        "method",
        "url",
        "user_agent",
        "port"
    ]

    def database_rows_to_dicts(self, rows):
        """
        SQLite'tan tuple olarak gelen olayları
        sözlük (dictionary) haline dönüştürür.

        Örneğin:

        (1, 'Sep 2 ...', 'auth', ...)

        yerine:

        {
            'id': 1,
            'timestamp': 'Sep 2 ...',
            'source': 'auth'
        }

        şeklinde kullanabiliriz.
        """

        events = []

        for row in rows:

            event = dict(
                zip(
                    self.EVENT_COLUMNS,
                    row
                )
            )

            events.append(event)

        return events

    # ========================================================
    # YIL BULMA
    # ========================================================

    def find_default_year(self, events):
        """
        Apache loglarında yıl bilgisi vardır.

        Örnek:
        02/Sep/2026:03:16:36 -0400

        auth.log ve syslog kayıtlarında ise genellikle
        yıl bilgisi bulunmaz.

        Bu yüzden event listesinde yıl içeren bir kayıt varsa
        onu diğer kayıtlar için referans yıl olarak kullanıyoruz.
        """

        for event in events:

            timestamp = event.get(
                "timestamp",
                ""
            )

            year_match = re.search(
                r"/(\d{4}):",
                timestamp
            )

            if year_match:
                return int(
                    year_match.group(1)
                )

        # Hiçbir kayıtta yıl yoksa mevcut yılı kullan.
        return datetime.now().year

    # ========================================================
    # TIMESTAMP PARSE
    # ========================================================

    def parse_timestamp(self, timestamp, default_year):
        """
        Farklı log timestamp formatlarını
        datetime nesnesine çevirmeye çalışır.

        Desteklenen formatlar:

        Apache:
        02/Sep/2026:03:16:36 -0400

        Linux auth/syslog:
        Sep 2 03:20:25
        """

        if not timestamp:
            return None

        # ----------------------------------------------------
        # APACHE FORMAT
        # ----------------------------------------------------

        try:

            apache_time = datetime.strptime(
                timestamp,
                "%d/%b/%Y:%H:%M:%S %z"
            )

            # Şimdilik korelasyon aynı yerel saat
            # sistemindeki kayıtlarla yapıldığı için
            # timezone bilgisini kaldırıyoruz.
            return apache_time.replace(
                tzinfo=None
            )

        except ValueError:
            pass

        # ----------------------------------------------------
        # LINUX SYSLOG / AUTH FORMAT
        # ----------------------------------------------------

        try:

            linux_time = datetime.strptime(
                f"{default_year} {timestamp}",
                "%Y %b %d %H:%M:%S"
            )

            return linux_time

        except ValueError:
            return None

    # ========================================================
    # ANA CORRELATION FONKSİYONU
    # ========================================================

    def correlate(self, events):
        """
        Event listesini analiz eder ve bulunan
        korelasyonları döndürür.
        """

        correlations = []

        default_year = self.find_default_year(
            events
        )

        # Her olayı diğer olaylarla karşılaştırıyoruz.
        for i in range(len(events)):

            event1 = events[i]

            for j in range(i + 1, len(events)):

                event2 = events[j]

                time1 = self.parse_timestamp(
                    event1.get("timestamp"),
                    default_year
                )

                time2 = self.parse_timestamp(
                    event2.get("timestamp"),
                    default_year
                )

                # Zaman bilgisi çözülemezse karşılaştırma yapma.
                if time1 is None or time2 is None:
                    continue

                # Olaylar arasındaki dakika farkı.
                time_difference = abs(
                    (time2 - time1).total_seconds()
                ) / 60

                # ============================================
                # RULE 1
                # WEB → FAILED AUTHENTICATION
                # ============================================

                if (
                    event1.get("event_type") == "web_request"
                    and
                    event2.get("event_type") == "authentication"
                    and
                    event2.get("status") == "failed"
                    and
                    event1.get("source_ip")
                    and
                    event1.get("source_ip")
                    == event2.get("source_ip")
                    and
                    time_difference <= 10
                ):

                    correlations.append(
                        {
                            "rule_id": "CORR-001",

                            "name":
                            "Web Activity → Failed Authentication",

                            "severity": "HIGH",

                            "source_ip":
                            event1.get("source_ip"),

                            "user":
                            event2.get("user"),

                            "event_ids": [
                                event1.get("id"),
                                event2.get("id")
                            ],

                            "time_difference_minutes":
                            round(time_difference, 2),

                            "reason":
                            (
                                "Aynı kaynak IP adresinden "
                                "10 dakika içinde web aktivitesi "
                                "ve başarısız kimlik doğrulama "
                                "olayı görüldü."
                            )
                        }
                    )

                # ============================================
                # RULE 2
                # AUTHENTICATION → SYSTEM ACTIVITY
                # ============================================

                if (
                    event1.get("event_type") == "authentication"
                    and
                    event1.get("status") == "failed"
                    and
                    event2.get("event_type") == "system_activity"
                    and
                    event1.get("user")
                    and
                    event1.get("user")
                    == event2.get("user")
                    and
                    time_difference <= 60
                ):

                    correlations.append(
                        {
                            "rule_id": "CORR-002",

                            "name":
                            "Authentication → System Activity",

                            "severity": "MEDIUM-HIGH",

                            "source_ip":
                            event1.get("source_ip"),

                            "user":
                            event1.get("user"),

                            "event_ids": [
                                event1.get("id"),
                                event2.get("id")
                            ],

                            "time_difference_minutes":
                            round(time_difference, 2),

                            "reason":
                            (
                                "Aynı kullanıcı için başarısız "
                                "authentication olayından sonra "
                                "60 dakika içinde sistem aktivitesi "
                                "görüldü. Bu ilişki nedensellik "
                                "kanıtı değildir."
                            )
                        }
                    )

                # ============================================
                # RULE 3
                # AYNI PROCESS
                # ============================================

                if (
                    event1.get("process")
                    and
                    event2.get("process")
                    and
                    event1.get("process")
                    == event2.get("process")
                    and
                    time_difference <= 10
                ):

                    correlations.append(
                        {
                            "rule_id": "CORR-003",

                            "name":
                            "Repeated Process Activity",

                            "severity": "MEDIUM",

                            "process":
                            event1.get("process"),

                            "event_ids": [
                                event1.get("id"),
                                event2.get("id")
                            ],

                            "time_difference_minutes":
                            round(time_difference, 2),

                            "reason":
                            (
                                "Aynı process tarafından "
                                "10 dakika içinde birden fazla "
                                "olay üretildi."
                            )
                        }
                    )

                # ============================================
                # RULE 4
                # AYNI EVENT TYPE + AYNI IP
                # ============================================

                if (
                    event1.get("event_type")
                    and
                    event1.get("event_type")
                    == event2.get("event_type")
                    and
                    event1.get("source_ip")
                    and
                    event1.get("source_ip")
                    == event2.get("source_ip")
                    and
                    time_difference <= 5
                ):

                    correlations.append(
                        {
                            "rule_id": "CORR-004",

                            "name":
                            "Repeated Event Type",

                            "severity": "MEDIUM",

                            "source_ip":
                            event1.get("source_ip"),

                            "event_type":
                            event1.get("event_type"),

                            "event_ids": [
                                event1.get("id"),
                                event2.get("id")
                            ],

                            "time_difference_minutes":
                            round(time_difference, 2),

                            "reason":
                            (
                                "Aynı kaynak IP tarafından "
                                "5 dakika içinde aynı türde "
                                "birden fazla olay üretildi."
                            )
                        }
                    )

        return correlations