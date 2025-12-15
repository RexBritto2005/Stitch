#!/usr/bin/env python3
"""
Snitch Python 3.13 - Remote Administration Tool
Main entry point for the application.

A modern, secure Python 3.13 compatible remote administration tool 
with unique AES encryption per installation.

Author: Snitch Team
Version: 1.0.0
Python: 3.13+
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Add Application directory to Python path
APP_DIR = Path(__file__).parent / "Application"
sys.path.insert(0, str(APP_DIR))

try:
    # Import required modules
    from Application.Snitch_cmd import command_handler
    from Application.Snitch_help import print_banner, print_error, print_info
    from Application.Snitch_utils import setup_logging
    from Application.Snitch_Vars.globals import APP_NAME, APP_VERSION
    
except ImportError as e:
    print(f"Failed to import required modules: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install -r win_requirements.txt")
    sys.exit(1)


def check_python_version() -> bool:
    """Check if Python version is 3.13 or higher."""
    if sys.version_info < (3, 13):
        print_error(f"Python 3.13+ required. Current version: {sys.version}")
        return False
    return True


def check_dependencies() -> bool:
    """Check if all required dependencies are available."""
    required_modules = [
        'Crypto',
        'PIL',
        'requests',
        'colorama',
        'dateutil'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print_error("Missing required dependencies:")
        for module in missing_modules:
            print(f"  - {module}")
        print("\nInstall dependencies with:")
        print("pip install -r win_requirements.txt")
        return False
    
    return True


def setup_environment() -> None:
    """Setup application environment."""
    # Setup logging
    log_level = os.getenv('SNITCH_LOG_LEVEL', 'INFO')
    setup_logging(log_level)
    
    # Log startup information
    logger = logging.getLogger(__name__)
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {sys.platform}")
    
    # Check for custom AES key in environment
    if os.getenv('Snitch_AES_KEY'):
        logger.info("Custom AES key detected in environment")


def main() -> int:
    """Main application entry point."""
    try:
        # Check Python version
        if not check_python_version():
            return 1
        
        # Check dependencies
        if not check_dependencies():
            return 1
        
        # Setup environment
        setup_environment()
        
        # Print banner
        print_banner()
        
        # Show startup information
        print_info(f"Welcome to {APP_NAME} v{APP_VERSION}")
        print_info("Type 'help' for available commands")
        print_info("Type 'exit' to quit")
        print()
        
        # Main command loop
        try:
            while True:
                try:
                    # Get user input
                    command_line = input("snitch> ").strip()
                    
                    # Handle command
                    if not command_handler.handle_command(command_line):
                        break  # Exit requested
                        
                except KeyboardInterrupt:
                    print("\nUse 'exit' command to quit")
                    continue
                except EOFError:
                    print("\nExiting...")
                    break
                    
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            logging.getLogger(__name__).error(f"Unexpected error in main loop: {e}")
            return 1
        
        return 0
        
    except Exception as e:
        print_error(f"Failed to start application: {e}")
        return 1


if __name__ == "__main__":
    # Ensure we're running as main module
    if len(sys.argv) > 1:
        print("Snitch Python 3.13 - Remote Administration Tool")
        print("Usage: python main.py")
        print("\nThis application does not accept command line arguments.")
        print("All interaction is done through the interactive console.")
        sys.exit(1)
    
    # Run main application
    exit_code = main()
    sys.exit(exit_code)