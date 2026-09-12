# ============================================================
# Mini SIEM - System Log Parser
# ============================================================

import re


class SystemParser:
    """
    Linux syslog/system log kayıtlarını ayrıştıran parser sınıfı.

    Amaç:
    - zaman
    - hostname
    - process
    - message
    - user
    - action
    - status

    gibi alanları çıkarmaktır.
    """

    # Genel syslog formatı:
    #
    # Sep 2 04:02:20 metasploitable stage5_system:
    # scenario=stage5 action=system_activity
    # user=msfadmin status=success

    SYSLOG_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) '
        r'(?P<hostname>\S+) '
        r'(?P<process>[^:]+): '
        r'(?P<message>.*)'
    )

    def parse_line(self, line):
        """
        Tek bir syslog satırını analiz eder.

        Satır uygun formattaysa sözlük döndürür.
        Değilse None döndürür.
        """

        line = line.strip()

        match = self.SYSLOG_PATTERN.match(line)

        if not match:
            return None

        # Regex ile temel alanları alıyoruz.
        event = match.groupdict()

        # Mini SIEM ortak alanları.
        event["source"] = "system"
        event["event_type"] = "system_activity"

        # Başlangıçta bu alanları boş kabul ediyoruz.
        event["user"] = None
        event["action"] = None
        event["status"] = None

        # Message içindeki key=value yapılarını kontrol ediyoruz.
        message = event["message"]

        # user=...
        user_match = re.search(
            r'user=(\S+)',
            message
        )

        if user_match:
            event["user"] = user_match.group(1)

        # action=...
        action_match = re.search(
            r'action=(\S+)',
            message
        )

        if action_match:
            event["action"] = action_match.group(1)

        # status=...
        status_match = re.search(
            r'status=(\S+)',
            message
        )

        if status_match:
            event["status"] = status_match.group(1)

        return event

    def parse_file(self, file_path):
        """
        Syslog dosyasının tamamını okur.

        Parse edilen olayları liste olarak döndürür.
        """

        events = []

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                event = self.parse_line(line)

                if event is not None:
                    events.append(event)

        return events


# ============================================================
# TEST BÖLÜMÜ
# ============================================================

if __name__ == "__main__":

    parser = SystemParser()

    # Daha önce laboratuvarda oluşturduğumuz
    # Stage 5 system activity kaydına uygun test satırı.
    test_log = (
        "Sep 2 04:02:20 metasploitable stage5_system: "
        "scenario=stage5 "
        "action=system_activity "
        "user=msfadmin "
        "status=success"
    )

    sonuc = parser.parse_line(test_log)

    print("System Parser Test Sonucu:")
    print(sonuc)