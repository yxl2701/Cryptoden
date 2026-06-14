"""Cryptoden entry point"""
import sys
import os

# Add project root to path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from cli import main

if __name__ == "__main__":
    sys.exit(main())