"""Frozen entry point for the bundled backend (PyInstaller): same CLI as `homesentry`."""

import multiprocessing

from homesentry.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
