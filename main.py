# ============================================================
# Mini SIEM / Security Event Correlator
# Ana Başlatma Dosyası
# ============================================================

# Ana masaüstü penceremizi ui klasöründen içe aktarıyoruz.
from ui.main_window import MiniSIEMApp

# Bu kontrol, dosya doğrudan çalıştırıldığında uygulamayı başlatır.
if __name__ == "__main__":
    # Mini SIEM uygulamasından bir nesne oluşturuyoruz.
    uygulama = MiniSIEMApp()

    # Masaüstü uygulamasını sürekli açık tutan ana döngüyü başlatıyoruz.
    uygulama.mainloop()
