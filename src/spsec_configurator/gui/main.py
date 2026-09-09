#!/usr/bin/env python3

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""GUI entry point. Launch: python -m spsec_configurator.gui.main"""

from __future__ import annotations

import sys
import argparse


def check_tkinter() -> bool:
    """Check if Tkinter is available"""
    try:
        import tkinter
        return True
    except ImportError:
        return False


def main(argv: "list[str] | None" = None) -> int:
    """Main entry point for GUI"""
    parser = argparse.ArgumentParser(
        description="SPsec Configurator GUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m spsec_configurator.gui.main
  python -m spsec_configurator.gui.main --interface can0
  python -m spsec_configurator.gui.main --keys-file /path/to/keys.txt
        """,
    )
    
    parser.add_argument(
        "-i", "--interface",
        default="vcan0",
        help="CAN interface to use (default: vcan0)",
    )
    parser.add_argument(
        "-k", "--keys-file",
        default="keys.txt",
        help="Path to keys file (default: keys.txt)",
    )
    parser.add_argument(
        "-c", "--config-file",
        default="groups_config.json",
        help="Path to configuration file (default: groups_config.json)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    
    args = parser.parse_args(argv)
    
    # Check Tkinter availability
    if not check_tkinter():
        print("Error: Tkinter is not available.", file=sys.stderr)
        print("Please install python3-tk:", file=sys.stderr)
        print("  sudo apt-get install python3-tk", file=sys.stderr)
        return 1
    
    # Configure logging if debug mode
    if args.debug:
        from ..core.logging_util import configure_logging
        configure_logging("DEBUG")
    
    # Import and run GUI
    try:
        from .main_window import MainWindow
        
        app = MainWindow()
        
        # Apply command-line settings
        settings = {
            "interface": args.interface,
            "keys_file": args.keys_file,
            "config_file": args.config_file,
        }
        app._settings.update(settings)
        app.interface_var.set(args.interface)
        app.config_panel.set_settings(settings)
        
        # Run the application
        app.mainloop()
        
        return 0
    except Exception as e:
        print(f"Error starting GUI: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

