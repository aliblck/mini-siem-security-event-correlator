# ============================================================
# Mini SIEM - Normalized Event Model
# ============================================================

from dataclasses import dataclass


@dataclass
class Event:
    """
    Mini SIEM içerisinde kullanılacak ortak olay modeli.

    Farklı log kaynaklarından gelen kayıtlar
    bu ortak yapıya dönüştürülecektir.
    """

    timestamp: str = ""
    source: str = ""

    source_ip: str = ""
    destination_ip: str = ""

    user: str = ""
    process: str = ""

    event_type: str = ""
    action: str = ""
    status: str = ""

    message: str = ""

    method: str = ""
    url: str = ""
    user_agent: str = ""

    port: int = 0

    def to_dict(self):
        """
        Event nesnesini sözlük (dictionary) formatına çevirir.

        Bu yapı ileride:
        - SQLite kayıtlarında
        - JSON raporlarında
        - GUI tablolarında

        kullanılacaktır.
        """

        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "process": self.process,
            "event_type": self.event_type,
            "action": self.action,
            "status": self.status,
            "message": self.message,
            "method": self.method,
            "url": self.url,
            "user_agent": self.user_agent,
            "port": self.port
        }


# ============================================================
# TEST BÖLÜMÜ
# ============================================================

if __name__ == "__main__":

    test_event = Event(
        timestamp="Sep 2 03:20:25",
        source="auth",
        source_ip="192.168.14.128",
        user="msfadmin",
        process="sshd[9081]",
        event_type="authentication",
        action="login",
        status="failed",
        port=55076
    )

    print("Normalized Event Test Sonucu:")
    print(test_event.to_dict())