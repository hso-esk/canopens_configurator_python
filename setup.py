# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

from setuptools import setup, find_packages

setup(
    name="spsec_configurator",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    # Keep in sync with requirements.txt.
    install_requires=[
        "python-can>=4.3.1",
        "cryptography>=42.0.0",
        "pycryptodome>=3.20.0",
        "pyserial>=3.5",
    ],
    entry_points={
        "console_scripts": [
            "spsec-cli=spsec_configurator.cli.main:main",
            "spsec-gui=spsec_configurator.gui.main:main",
            "spsec-group=spsec_configurator.cli.group_cli:main",
            "spsec-keys=spsec_configurator.cli.keys_cli:main",
            "spsec-repeat=spsec_configurator.cli.repeat_cli:main",
            "spsec-only-repeat=spsec_configurator.cli.only_repeat_cli:main",
        ],
    },
)
