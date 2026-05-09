"""
IASSING Encryptor and Decryptor
Main entry point - runs the UI application.

Imports UI and algorithm components from separate modules:
  cipher.py — XDES-A cipher implementation
  ui.py     — Tkinter UI application
"""

from ui import XDESApp

if __name__ == "__main__":
    app = XDESApp()
    app.mainloop()