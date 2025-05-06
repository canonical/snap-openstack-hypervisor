# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging
import sys


def setup_root_logging():
    """Sets up the root logging level for the application."""
    verbose = False
    for arg in sys.argv:
        if arg.lower() in ["-v", "--verbose"]:
            verbose = True
            break

    # Reduce pyroute2 logging to warnings only, as it's extra verbose.
    for namespace in ("pyroute2",):
        logging.getLogger(namespace).setLevel(logging.WARNING)

    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
