# ============================================================
# Mini SIEM - Attack Timeline Builder
# Saldırı Zaman Çizelgesi Oluşturucu
# ============================================================

from detection.correlation import CorrelationEngine


class TimelineBuilder:
    """
    Veritabanındaki güvenlik olaylarını zaman sırasına koyar
    ve Attack Timeline için kullanılabilir hale getirir.
    """

    def __init__(self):
        # Timestamp çözümleme işlemleri için mevcut
        # Correlation Engine fonksiyonlarını kullanıyoruz.
        self.correlation_engine = CorrelationEngine()

    def get_event_title(self, event):
        """
        Event türüne göre kullanıcıya gösterilecek
        anlaşılır olay başlığını oluşturur.
        """

        # Apache / Web olayı
        if event.get("event_type") == "web_request":

            user_agent = event.get("user_agent", "")
            url = event.get("url", "")

            # Şüpheli User-Agent veya URL varsa
            if "Suspicious" in user_agent:
                return "Suspicious Web Request / Şüpheli Web İsteği"

            return "Web Activity / Web Aktivitesi"

        # Authentication olayı
        if event.get("event_type") == "authentication":

            if event.get("status") == "failed":
                return "Failed Authentication / Başarısız Giriş"

            return "Authentication / Kimlik Doğrulama"

        # System olayı
        if event.get("event_type") == "system_activity":
            return "System Activity / Sistem Aktivitesi"

        # Diğer olaylar
        return event.get("event_type", "Unknown Event")

    def build_timeline(self, events):
        """
        Eventleri timestamp bilgisine göre sıralar
        ve Timeline kayıtları oluşturur.
        """

        timeline = []

        # Linux loglarında yıl olmadığı için
        # Apache kaydındaki yılı referans alıyoruz.
        default_year = self.correlation_engine.find_default_year(
            events
        )

        for event in events:

            parsed_time = self.correlation_engine.parse_timestamp(
                event.get("timestamp", ""),
                default_year
            )

            # Timestamp çözülemiyorsa listeye eklemiyoruz.
            if parsed_time is None:
                continue

            timeline_item = {
                "event_id": event.get("id"),
                "timestamp": event.get("timestamp", ""),
                "parsed_time": parsed_time,
                "title": self.get_event_title(event),
                "source": event.get("source", ""),
                "source_ip": event.get("source_ip", ""),
                "user": event.get("user", ""),
                "process": event.get("process", ""),
                "event_type": event.get("event_type", ""),
                "status": event.get("status", ""),
                "url": event.get("url", "")
            }

            timeline.append(
                timeline_item
            )

        # Olayları zamana göre eski → yeni sıralıyoruz.
        timeline.sort(
            key=lambda item: item["parsed_time"]
        )

        return timeline