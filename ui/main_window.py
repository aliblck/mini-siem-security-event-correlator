# ============================================================
# Mini SIEM
# Ana Masaüstü Arayüzü
# ============================================================

# tkinter Python'un masaüstü arayüz oluşturma kütüphanesidir.
import tkinter as tk


class MiniSIEMApp(tk.Tk):
    """
    Mini SIEM uygulamasının ana masaüstü penceresi.

    Bu sınıf:
    - Ana pencereyi oluşturur.
    - Sol taraftaki menüyü oluşturur.
    - Dashboard ekranını gösterir.
    - Menü butonları arasında geçiş yapılmasını sağlar.
    """

    def __init__(self):

        # Tkinter ana pencere sınıfını başlatıyoruz.
        super().__init__()

        # ====================================================
        # ANA PENCERE AYARLARI
        # ====================================================

        # Programın üst kısmında görünen pencere başlığı.
        self.title(
            "Mini SIEM - Security Event Correlator / Güvenlik Olayı İlişkilendirici"
        )

        # Program ilk açıldığında pencerenin boyutu.
        self.geometry("1200x700")

        # Pencerenin daha fazla küçültülmesini engeller.
        self.minsize(1000, 600)

        # Ana pencerenin arka plan rengi.
        self.configure(bg="#F3F4F6")

        # ====================================================
        # SOL MENÜ
        # ====================================================

        # Programın sol tarafında bulunan menü alanı.
        self.sol_menu = tk.Frame(
            self,
            bg="#1F2937",
            width=250
        )

        self.sol_menu.pack(
            side="left",
            fill="y"
        )

        # Menü alanının genişliğinin sabit kalmasını sağlar.
        self.sol_menu.pack_propagate(False)

        # ====================================================
        # UYGULAMA BAŞLIĞI
        # ====================================================

        tk.Label(
            self.sol_menu,
            text="MINI SIEM",
            bg="#1F2937",
            fg="white",
            font=("Arial", 20, "bold")
        ).pack(
            pady=(30, 5)
        )

        # İngilizce teknik ismin yanında Türkçe anlamını gösteriyoruz.
        tk.Label(
            self.sol_menu,
            text="Security Event Correlator\nGüvenlik Olayı İlişkilendirici",
            bg="#1F2937",
            fg="#D1D5DB",
            font=("Arial", 9),
            justify="center"
        ).pack(
            pady=(0, 25)
        )

        # ====================================================
        # MENÜ BUTONLARI
        # ====================================================

        self.menu_butonu_olustur(
            "Dashboard / Ana Panel",
            self.dashboard_goster
        )

        self.menu_butonu_olustur(
            "Log Import / Log Aktarımı",
            self.log_import_goster
        )

        self.menu_butonu_olustur(
            "Events / Olaylar",
            self.events_goster
        )

        self.menu_butonu_olustur(
            "Alerts / Alarmlar",
            self.alerts_goster
        )

        self.menu_butonu_olustur(
            "Incidents / Vakalar",
            self.incidents_goster
        )

        self.menu_butonu_olustur(
            "Timeline / Zaman Çizelgesi",
            self.timeline_goster
        )

        self.menu_butonu_olustur(
            "Reports / Raporlar",
            self.reports_goster
        )

        # ====================================================
        # ANA İÇERİK ALANI
        # ====================================================

        # Menüye tıklayınca açılan sayfalar burada gösterilecek.
        self.icerik_alani = tk.Frame(
            self,
            bg="#F3F4F6"
        )

        self.icerik_alani.pack(
            side="right",
            fill="both",
            expand=True
        )

        # Program açıldığında ilk olarak Dashboard gösterilir.
        self.dashboard_goster()

    # ========================================================
    # MENÜ BUTONU OLUŞTURMA
    # ========================================================

    def menu_butonu_olustur(self, yazi, komut):
        """
        Sol menüde bulunan butonları oluşturur.

        yazi:
            Butonun üzerinde görünen yazıdır.

        komut:
            Butona tıklanınca çalışacak fonksiyondur.
        """

        buton = tk.Button(
            self.sol_menu,
            text=yazi,
            command=komut,
            bg="#1F2937",
            fg="white",

            # Fare ile tıklanınca kullanılacak renkler.
            activebackground="#374151",
            activeforeground="white",

            # Butonun kenarlığını kaldırıyoruz.
            bd=0,

            # Yazıyı sola hizalıyoruz.
            anchor="w",

            padx=20,
            pady=12,

            font=("Arial", 10)
        )

        # Buton menünün yatay genişliğini tamamen kaplar.
        buton.pack(
            fill="x"
        )

    # ========================================================
    # EKRAN TEMİZLEME
    # ========================================================

    def ekrani_temizle(self):
        """
        Kullanıcı başka bir menüye geçtiğinde
        sağ taraftaki eski içeriği temizler.

        Böylece yeni sayfa aynı alan içerisinde gösterilir.
        """

        for widget in self.icerik_alani.winfo_children():
            widget.destroy()

    # ========================================================
    # DASHBOARD / ANA PANEL
    # ========================================================

    def dashboard_goster(self):
        """
        Mini SIEM uygulamasının ana özet ekranını gösterir.
        """

        # Önce eski sayfayı temizliyoruz.
        self.ekrani_temizle()

        # Sayfa başlığı.
        tk.Label(
            self.icerik_alani,
            text="Security Dashboard / Güvenlik Ana Paneli",
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 10)
        )

        # Dashboard açıklaması.
        tk.Label(
            self.icerik_alani,
            text="Mini SIEM güvenlik olaylarının genel görünümü",
            bg="#F3F4F6",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            anchor="w",
            padx=30
        )

        # ====================================================
        # ÖZET KARTLARI
        # ====================================================

        kart_alani = tk.Frame(
            self.icerik_alani,
            bg="#F3F4F6"
        )

        kart_alani.pack(
            fill="x",
            padx=30,
            pady=30
        )

        # Şimdilik değerler 0.
        # Daha sonra SQLite veritabanından gerçek değerleri alacağız.

        self.ozet_karti_olustur(
            kart_alani,
            "Total Events\nToplam Olay",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Alerts\nAlarmlar",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Incidents\nVakalar",
            "0"
        )

        self.ozet_karti_olustur(
            kart_alani,
            "Critical\nKritik",
            "0"
        )

        # ====================================================
        # SON GÜVENLİK ALARMLARI
        # ====================================================

        son_alarmlar = tk.LabelFrame(
            self.icerik_alani,
            text=" Latest Security Alerts / Son Güvenlik Alarmları ",
            bg="white",
            fg="#111827",
            font=("Arial", 11, "bold")
        )

        son_alarmlar.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 30)
        )

        # Henüz detection sistemi olmadığı için bilgi mesajı gösteriyoruz.
        tk.Label(
            son_alarmlar,
            text="Henüz güvenlik alarmı bulunmuyor.",
            bg="white",
            fg="#6B7280",
            font=("Arial", 11)
        ).pack(
            pady=50
        )

    # ========================================================
    # DASHBOARD ÖZET KARTI
    # ========================================================

    def ozet_karti_olustur(self, parent, baslik, deger):
        """
        Dashboard üzerinde bulunan küçük bilgi kartlarını oluşturur.

        Örneğin:
        Total Events
        Alerts
        Incidents
        Critical
        """

        kart = tk.Frame(
            parent,
            bg="white",
            bd=1,
            relief="solid"
        )

        kart.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        # Kart başlığı.
        tk.Label(
            kart,
            text=baslik,
            bg="white",
            fg="#6B7280",
            font=("Arial", 10),
            justify="center"
        ).pack(
            pady=(20, 5)
        )

        # Kartın sayısal değeri.
        tk.Label(
            kart,
            text=deger,
            bg="white",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            pady=(0, 20)
        )

    # ========================================================
    # BASİT SAYFA GÖSTERME
    # ========================================================

    def basit_sayfa_goster(self, baslik):
        """
        Henüz içeriğini geliştirmediğimiz menülerin
        temel sayfasını gösterir.

        İlerleyen aşamalarda bu sayfaların içlerini
        gerçek özelliklerle dolduracağız.
        """

        self.ekrani_temizle()

        tk.Label(
            self.icerik_alani,
            text=baslik,
            bg="#F3F4F6",
            fg="#111827",
            font=("Arial", 24, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=30
        )

    # ========================================================
    # LOG IMPORT / LOG AKTARIMI
    # ========================================================

    def log_import_goster(self):
        self.basit_sayfa_goster(
            "Log Import / Log Aktarımı"
        )

    # ========================================================
    # EVENTS / OLAYLAR
    # ========================================================

    def events_goster(self):
        self.basit_sayfa_goster(
            "Normalized Events / Normalize Edilmiş Olaylar"
        )

    # ========================================================
    # ALERTS / ALARMLAR
    # ========================================================

    def alerts_goster(self):
        self.basit_sayfa_goster(
            "Security Alerts / Güvenlik Alarmları"
        )

    # ========================================================
    # INCIDENTS / VAKALAR
    # ========================================================

    def incidents_goster(self):
        self.basit_sayfa_goster(
            "Incidents / Vakalar"
        )

    # ========================================================
    # TIMELINE / ZAMAN ÇİZELGESİ
    # ========================================================

    def timeline_goster(self):
        self.basit_sayfa_goster(
            "Attack Timeline / Saldırı Zaman Çizelgesi"
        )

    # ========================================================
    # REPORTS / RAPORLAR
    # ========================================================

    def reports_goster(self):
        self.basit_sayfa_goster(
            "Incident Reports / Olay Raporları"
        )