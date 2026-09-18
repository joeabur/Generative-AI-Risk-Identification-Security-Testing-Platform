from collections.abc import Callable
from pathlib import Path


class KillSwitch:
    """Three ways to stop a run, all checked fresh on every read rather than
    cached, so tripping one takes effect on the very next scope check:

    - an in-memory flag (`.trip()`, e.g. from a SIGTERM handler),
    - an optional sentinel file whose mere existence trips it,
    - an optional `probe` callback, which is how a cancellation requested in
      one process (the API) reaches a run executing in another (a Celery
      worker) — see `app/workers/tasks.py`.

    Once tripped it stays tripped: a run that was stopped must not resume
    because a Redis key expired or a file was deleted mid-flight.
    """

    def __init__(
        self, *, sentinel_path: Path | None = None, probe: Callable[[], bool] | None = None
    ) -> None:
        self._tripped = False
        self._sentinel_path = sentinel_path
        self._probe = probe

    def trip(self) -> None:
        self._tripped = True

    @property
    def tripped(self) -> bool:
        if self._tripped:
            return True
        sentinel_present = self._sentinel_path is not None and self._sentinel_path.exists()
        probe_tripped = self._probe is not None and self._probe()
        if sentinel_present or probe_tripped:
            self._tripped = True
        return self._tripped
