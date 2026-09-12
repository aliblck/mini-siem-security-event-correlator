# ============================================================
# Mini SIEM - Event Normalizer
# ============================================================

# Ortak Event modelimizi içe aktarıyoruz.
from models.event import Event


class EventNormalizer:
    """
    Farklı log parserlarından gelen verileri
    ortak Mini SIEM Event formatına dönüştürür.
    """

    @staticmethod
    def normalize_apache(data):
        """
        Apache parser çıktısını ortak Event modeline çevirir.
        """

        return Event(
            timestamp=data.get("timestamp", ""),
            source=data.get("source", "apache_access"),
            source_ip=data.get("source_ip", ""),

            event_type="web_request",

            # Apache olayında yapılan işlem HTTP metodudur.
            action=data.get("method", ""),

            # HTTP durum kodunu string olarak ortak status alanına alıyoruz.
            status=str(data.get("status", "")),

            method=data.get("method", ""),
            url=data.get("url", ""),
            user_agent=data.get("user_agent", "")
        )

    @staticmethod
    def normalize_auth(data):
        """
        Authentication parser çıktısını ortak Event modeline çevirir.
        """

        return Event(
            timestamp=data.get("timestamp", ""),
            source=data.get("source", "auth"),
            source_ip=data.get("source_ip", ""),

            user=data.get("user", ""),
            process=data.get("process", ""),

            event_type=data.get(
                "event_type",
                "authentication"
            ),

            action=data.get("action", ""),
            status=data.get("status", ""),

            port=data.get("port", 0)
        )

    @staticmethod
    def normalize_system(data):
        """
        System parser çıktısını ortak Event modeline çevirir.
        """

        return Event(
            timestamp=data.get("timestamp", ""),
            source=data.get("source", "system"),

            user=data.get("user") or "",
            process=data.get("process", ""),

            event_type=data.get(
                "event_type",
                "system_activity"
            ),

            action=data.get("action") or "",
            status=data.get("status") or "",

            message=data.get("message", "")
        )


# ============================================================
# TEST BÖLÜMÜ
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # APACHE TEST VERİSİ
    # --------------------------------------------------------

    apache_data = {
        "source_ip": "192.168.14.128",
        "timestamp": "02/Sep/2026:03:16:36 -0400",
        "method": "GET",
        "url": "/dvwa/?id=test",
        "protocol": "HTTP/1.1",
        "status": 302,
        "size": 154,
        "referrer": "-",
        "user_agent": "MiniSIEM-Stage5-Suspicious/1.0",
        "source": "apache_access"
    }

    # --------------------------------------------------------
    # AUTH TEST VERİSİ
    # --------------------------------------------------------

    auth_data = {
        "timestamp": "Sep 2 03:20:25",
        "hostname": "metasploitable",
        "process": "sshd[9081]",
        "user": "msfadmin",
        "source_ip": "192.168.14.128",
        "port": 55076,
        "protocol": "ssh2",
        "source": "auth",
        "event_type": "authentication",
        "action": "login",
        "status": "failed"
    }

    # --------------------------------------------------------
    # SYSTEM TEST VERİSİ
    # --------------------------------------------------------

    system_data = {
        "timestamp": "Sep 2 04:02:20",
        "hostname": "metasploitable",
        "process": "stage5_system",
        "message": (
            "scenario=stage5 action=system_activity "
            "user=msfadmin status=success"
        ),
        "source": "system",
        "event_type": "system_activity",
        "user": "msfadmin",
        "action": "system_activity",
        "status": "success"
    }

    # Normalizer nesnesi oluşturmaya gerek yok.
    # Çünkü fonksiyonlarımız staticmethod olarak tanımlandı.

    apache_event = EventNormalizer.normalize_apache(apache_data)
    auth_event = EventNormalizer.normalize_auth(auth_data)
    system_event = EventNormalizer.normalize_system(system_data)

    print("\n--- APACHE NORMALIZED EVENT ---")
    print(apache_event.to_dict())

    print("\n--- AUTH NORMALIZED EVENT ---")
    print(auth_event.to_dict())

    print("\n--- SYSTEM NORMALIZED EVENT ---")
    print(system_event.to_dict())