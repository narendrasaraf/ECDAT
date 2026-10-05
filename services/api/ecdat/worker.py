"""Trusted host controller. Run separately from the HTTP process."""
from .store import initialize
from .jobs import worker_loop, stop_event

if __name__=='__main__':
    initialize()
    try:worker_loop()
    except KeyboardInterrupt:stop_event.set()
