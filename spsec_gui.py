#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

import sys
import os

# Add src to python path to allow imports from spsec_configurator
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from spsec_configurator.gui.main import main

if __name__ == "__main__":
    sys.exit(main())
