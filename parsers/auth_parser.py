# ============================================================
# Mini SIEM - Authentication Log Parser
# ============================================================

import re


class AuthParser:
    """
    Linux auth.log kayıtlarını ayrıştıran parser sınıfı.

    Özellikle SSH kimlik doğrulama olaylarından:
    - zaman
    - kullanıcı
    - kaynak IP
    - port
    - giriş sonucu
    - işlem adı

    gibi bilgileri çıkarır.
    """

    # --------------------------------------------------------
    # FAILED PASSWORD
    # Örnek:
    # Sep 2 03:20:25 metasploitable sshd[9081]:
    # Failed password for msfadmin from 192.168.14.128 port 55076 ssh2
    # --------------------------------------------------------

    FAILED_PASSWORD_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) '
        r'(?P<hostname>\S+) '
        r'(?P<process>sshd\[\d+\]): '
        r'Failed password for '
        r'(?P<user>\S+) '
        r'from (?P<source_ip>\S+) '
        r'port (?P<port>\d+) '
        r'(?P<protocol>\S+)'
    )

    # --------------------------------------------------------
    # PAM AUTHENTICATION FAILURE
    # Örnek:
    # Sep 2 03:20:23 metasploitable sshd[9081]:
    # pam_unix(sshd:auth): authentication failure;
    # rhost=192.168.14.128 user=msfadmin
    # --------------------------------------------------------

    AUTH_FAILURE_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) '
        r'(?P<hostname>\S+) '
        r'(?P<process>sshd\[\d+\]): '
        r'.*authentication failure;'
        r'.*rhost=(?P<source_ip>\S+)'
        r'.*user=(?P<user>\S+)'
    )

    def parse_line(self, line):
        """
        Tek bir auth.log satırını analiz eder.

        Tanınan bir authentication olayı varsa sözlük döndürür.
        Uygun değilse None döndürür.
        """

        line = line.strip()

        # Önce Failed password formatını kontrol ediyoruz.
        match = self.FAILED_PASSWORD_PATTERN.search(line)

        if match:
            event = match.groupdict()

            # Port değerini sayı haline getiriyoruz.
            event["port"] = int(event["port"])

            # Ortak alanlar ekleniyor.
            event["source"] = "auth"
            event["event_type"] = "authentication"
            event["action"] = "login"
            event["status"] = "failed"

            return event

        # Failed password değilse PAM authentication failure
        # formatını kontrol ediyoruz.
        match = self.AUTH_FAILURE_PATTERN.search(line)

        if match:
            event = match.groupdict()

            event["source"] = "auth"
            event["event_type"] = "authentication"
            event["action"] = "login"
            event["status"] = "failed"

            return event

        # Tanınan bir auth olayı bulunamadı.
        return None

    def parse_file(self, file_path):
        """
        auth.log dosyasının tamamını okur.

        Parser tarafından tanınan kayıtları
        bir liste içerisinde döndürür.
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

    parser = AuthParser()

    # Daha önce laboratuvarda gördüğümüz auth.log biçimine
    # uygun test satırı.
    test_log = (
        "Sep 2 03:20:25 metasploitable sshd[9081]: "
        "Failed password for msfadmin "
        "from 192.168.14.128 port 55076 ssh2"
    )

    sonuc = parser.parse_line(test_log)

    print("Auth Parser Test Sonucu:")
    print(sonuc)