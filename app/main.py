import sys
import logging

from PySide6.QtWidgets import QApplication

from app.ui.main_window import MainWindow
from app.ui.theme import STYLESHEET

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PCAP Bloodhound")
    app.setOrganizationName("BardSec")
    app.setStyleSheet(STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
