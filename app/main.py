import sys
from pathlib import Path

from PySide6.QtCore import Property, QObject, QUrl, Signal, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine

import scl_sanitizer


def resource_path(relative_path: str) -> Path:
    """Return a path for source execution or a PyInstaller bundle."""
    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent

    return base_path / relative_path


class SanitizerBridge(QObject):
    statusChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._status = "Ready"

    @Slot(QUrl, result=str)
    def url_to_local_file(self, url: QUrl) -> str:
        return url.toLocalFile()

    @Property(str, notify=statusChanged)
    def status(self):
        return self._status

    def set_status(self, value: str):
        if self._status != value:
            self._status = value
            self.statusChanged.emit(value)

    @Slot(str, bool, int, result=str)
    def sanitize_file(
        self,
        file_path: str,
        use_hash_seed: bool,
        seed: int,
    ) -> str:
        try:
            if use_hash_seed:
                output_path = scl_sanitizer.sanitize(
                    file_path,
                    hash_seed=True,
                )
            else:
                output_path = scl_sanitizer.sanitize(
                    file_path,
                    seed=seed,
                )

            result = str(output_path)
            self.set_status(f"Completed: {result}")
            return result

        except Exception as exc:
            self.set_status(f"Error: {exc}")
            raise


def main() -> int:
    app = QGuiApplication(sys.argv)
    engine = QQmlApplicationEngine()

    bridge = SanitizerBridge()
    engine.rootContext().setContextProperty(
        "SanitizerBridge",
        bridge,
    )

    if getattr(sys, "frozen", False):
        qml_path = resource_path("gui/main.qml")
    else:
        qml_path = resource_path("gui/main.qml")

    engine.load(QUrl.fromLocalFile(str(qml_path)))

    if not engine.rootObjects():
        raise RuntimeError(f"Failed to load QML: {qml_path}")

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
