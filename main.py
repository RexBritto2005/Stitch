#!/usr/bin/env python3
# Copyright (c) 2017, Nathan Lopez
# Stitch is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.
# Modernized for Python 3.13 - Consolidated Version

"""
Stitch - Cross Platform Python Remote Administration Tool
Consolidated main entry point with full functionality.
"""

from __future__ import annotations
import sys
import warnings
import signal
import os

# Suppress non-critical warnings
warnings.filterwarnings("ignore", message=".*readline.*")

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print('\n\n[*] Stitch shutdown requested by user')
    print('[-] Exiting Stitch...')
    sys.exit(0)

def main():
    """Main function with integrated functionality."""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Display startup banner
        print("=" * 60)
        print("    Stitch Python 3.13 - Remote Administration Tool")
        print("=" * 60)
        print()
        print("Available Commands:")
        print("  listen <port>    - Start listening for connections")
        print("  connect <ip> <port> - Connect to remote payload")
        print("  sessions         - Show active sessions")
        print("  shell <ip>       - Connect to a session")
        print("  showkey          - Display AES encryption key")
        print("  addkey <key>     - Add AES encryption key")
        print("  history          - Show connection history")
        print("  pwd              - Show current directory")
        print("  ls/dir           - List directory contents")
        print("  cd <path>        - Change directory")
        print("  help             - Show all commands")
        print("  exit             - Exit Stitch")
        print()
        print("Press Ctrl+C to exit at any time")
        print("=" * 60)
        
        # Import and start the server
        from Application.stitch_cmd import stitch_server
        
        # Create server instance
        server = stitch_server()
        
        # Start listening on default port
        print("\n[*] Starting server on port 4040...")
        server.do_listen('4040')
        
        # Interactive command loop
        print("\n[+] Stitch is ready! Type commands below:")
        
        while True:
            try:
                # Get user input
                user_input = input(server.prompt).strip()
                
                if not user_input:
                    continue
                    
                # Handle exit commands
                if user_input.lower() in ['exit', 'quit', 'q']:
                    server.do_exit()
                    break
                
                # Process command
                stop = server.onecmd(user_input)
                if stop:
                    break
                    
            except EOFError:
                print("\n[*] EOF received, exiting...")
                server.do_exit()
                break
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' command to quit properly")
                continue
            except Exception as e:
                print(f"[!] Error processing command: {e}")
                continue
                
    except ImportError as e:
        print(f"\n[!] Import Error: {e}")
        print("[*] Please ensure all dependencies are installed:")
        if sys.platform.startswith('win'):
            print("    pip install -r win_requirements.txt")
        elif sys.platform.startswith('darwin'):
            print("    pip install -r osx_requirements.txt")
        else:
            print("    pip install -r lnx_requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()