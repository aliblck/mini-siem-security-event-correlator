# ============================================================
# Mini SIEM - Detection Rules
# Tespit Kuralları
# ============================================================

from detection.correlation import CorrelationEngine


class DetectionEngine:
    """
    Normalize edilmiş güvenlik olayları üzerinde
    detection / tespit kurallarını çalıştırır.

    Bu sınıf şu davranışları kontrol eder:

    - Web Enumeration
    - Suspicious Web Request
    - Multiple Failed Authentication

    Yeni kurallar daha sonra aynı yapıya eklenebilir.
    """

    def __init__(self):

        # Timestamp çözümlemek için mevcut
        # Correlation Engine fonksiyonlarını kullanıyoruz.
        self.time_helper = CorrelationEngine()

    # ========================================================
    # WEB ENUMERATION
    # ========================================================

    def detect_web_enumeration(self, events):
        """
        Aynı kaynak IP adresinin 30 saniye içerisinde
        3 veya daha fazla farklı URL'ye erişmesini kontrol eder.

        Tespit edilirse HIGH severity üretir.
        """

        detections = []

        default_year = self.time_helper.find_default_year(
            events
        )

        # Sadece web eventlerini alıyoruz.
        web_events = []

        for event in events:

            if (
                event.get("event_type") == "web_request"
                and
                event.get("source_ip")
            ):

                parsed_time = self.time_helper.parse_timestamp(
                    event.get("timestamp", ""),
                    default_year
                )

                if parsed_time is not None:

                    event_copy = event.copy()

                    event_copy["_parsed_time"] = parsed_time

                    web_events.append(
                        event_copy
                    )

        # Kaynak IP'lere göre grupluyoruz.
        source_ips = set(
            event.get("source_ip")
            for event in web_events
        )

        for source_ip in source_ips:

            ip_events = [
                event
                for event in web_events
                if event.get("source_ip") == source_ip
            ]

            # Zaman sırasına koyuyoruz.
            ip_events.sort(
                key=lambda event: event["_parsed_time"]
            )

            for i in range(len(ip_events)):

                start_event = ip_events[i]

                window_events = []

                for event in ip_events[i:]:

                    difference = (
                        event["_parsed_time"]
                        - start_event["_parsed_time"]
                    ).total_seconds()

                    if 0 <= difference <= 30:
                        window_events.append(event)

                # Aynı pencere içindeki farklı URL'ler.
                urls = set(
                    event.get("url", "")
                    for event in window_events
                    if event.get("url")
                )

                if len(urls) >= 3:

                    detections.append(
                        {
                            "rule_id": "DET-001",
                            "name": "Web Enumeration",
                            "severity": "MEDIUM",
                            "source_ip": source_ip,
                            "event_ids": [
                                event.get("id")
                                for event in window_events
                            ],
                            "reason": (
                                "Aynı kaynak IP adresinden "
                                "30 saniye içinde en az 3 farklı "
                                "URL'ye erişim tespit edildi."
                            )
                        }
                    )

                    # Aynı olay grubunu tekrar tekrar
                    # üretmemek için bu IP için duruyoruz.
                    break

        return detections

    # ========================================================
    # SUSPICIOUS WEB REQUEST
    # ========================================================

    def detect_suspicious_web_request(self, events):
        """
        Şüpheli URL veya User-Agent içeren
        HTTP isteklerini kontrol eder.

        Tespit edilirse HIGH severity üretir.
        """

        detections = []

        suspicious_patterns = [
            "' or ",
            "%27",
            "union select",
            "../",
            "<script",
            "suspicious"
        ]

        for event in events:

            if event.get("event_type") != "web_request":
                continue

            url = str(
                event.get("url", "")
            ).lower()

            user_agent = str(
                event.get("user_agent", "")
            ).lower()

            combined_text = (
                url + " " + user_agent
            )

            suspicious = False

            for pattern in suspicious_patterns:

                if pattern in combined_text:

                    suspicious = True
                    break

            if suspicious:

                detections.append(
                    {
                        "rule_id": "DET-002",
                        "name": "Suspicious Web Request",
                        "severity": "HIGH",
                        "source_ip":
                        event.get("source_ip", ""),

                        "event_ids": [
                            event.get("id")
                        ],

                        "reason": (
                            "HTTP isteğinde şüpheli URL "
                            "veya User-Agent göstergesi "
                            "tespit edildi."
                        )
                    }
                )

        return detections

    # ========================================================
    # MULTIPLE FAILED AUTHENTICATION
    # ========================================================

    def detect_multiple_failed_auth(self, events):
        """
        Aynı kaynak IP adresinden 5 dakika içerisinde
        en az 5 başarısız authentication olayını kontrol eder.

        Detection seviyesi MEDIUM'dur.

        Daha sonra Risk Scoring katmanı bu davranışı,
        diğer olaylarla birlikte değerlendirerek
        daha yüksek incident seviyesine çıkarabilir.
        """

        detections = []

        default_year = self.time_helper.find_default_year(
            events
        )

        auth_events = []

        for event in events:

            if (
                event.get("event_type") == "authentication"
                and
                event.get("status") == "failed"
                and
                event.get("source_ip")
            ):

                parsed_time = self.time_helper.parse_timestamp(
                    event.get("timestamp", ""),
                    default_year
                )

                if parsed_time is not None:

                    event_copy = event.copy()

                    event_copy["_parsed_time"] = parsed_time

                    auth_events.append(
                        event_copy
                    )

        source_ips = set(
            event.get("source_ip")
            for event in auth_events
        )

        for source_ip in source_ips:

            ip_events = [
                event
                for event in auth_events
                if event.get("source_ip") == source_ip
            ]

            ip_events.sort(
                key=lambda event: event["_parsed_time"]
            )

            for i in range(len(ip_events)):

                start_event = ip_events[i]

                window_events = []

                for event in ip_events[i:]:

                    difference = (
                        event["_parsed_time"]
                        - start_event["_parsed_time"]
                    ).total_seconds()

                    if 0 <= difference <= 300:
                        window_events.append(event)

                if len(window_events) >= 5:

                    detections.append(
                        {
                            "rule_id": "DET-003",
                            "name":
                            "Multiple Failed Authentication",

                            "severity": "HIGH",

                            "source_ip":
                            source_ip,

                            "user":
                            window_events[0].get(
                                "user",
                                ""
                            ),

                            "event_ids": [
                                event.get("id")
                                for event in window_events
                            ],

                            "reason": (
                                "Aynı kaynak IP adresinden "
                                "5 dakika içinde en az 5 "
                                "başarısız authentication "
                                "olayı tespit edildi."
                            )
                        }
                    )

                    break

        return detections

    # ========================================================
    # TÜM DETECTION KURALLARI
    # ========================================================

    def run_all_rules(self, events):
        """
        Tanımlı bütün detection kurallarını çalıştırır.
        """

        detections = []

        detections.extend(
            self.detect_web_enumeration(events)
        )

        detections.extend(
            self.detect_suspicious_web_request(events)
        )

        detections.extend(
            self.detect_multiple_failed_auth(events)
        )

        return detections