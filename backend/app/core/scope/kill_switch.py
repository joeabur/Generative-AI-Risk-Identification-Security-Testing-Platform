from pathlib import Path


class KillSwitch:
    """Two ways to stop a run: an in-memory flag (`.trip()`, e.g. from a
    SIGTERM handler or an authenticated "cancel" API call) and an optional
    sentinel file whose mere existence trips it — checked fresh on every
    read rather than cached, so `touch`ing the file mid-run takes effect on
    the very next scope check.
    """

    def __init__(self, *, sentinel_path: Path | None = None) -> None:
        self._tripped = False
        self._sentinel_path = sentinel_path

    def trip(self) -> None:
        self._tripped = True

    @property
    def tripped(self) -> bool:
        if self._tripped:
            return True
        if self._sentinel_path is not None and self._sentinel_path.exists():
            self._tripped = True
        return self._tripped
