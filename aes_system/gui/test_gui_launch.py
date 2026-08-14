#!/usr/bin/env python3
"""
Test AES GUI launch and basic functionality
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
sys.path.insert(0, python_dir)

print("Testing AES GUI launch...")

try:
    from aes_gui import AESMainWindow
    print("✓ AESMainWindow imported successfully")
except Exception as e:
    print(f"✗ Failed to import AESMainWindow: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

try:
    app = QApplication(sys.argv)
    print("✓ QApplication created")
    
    window = AESMainWindow()
    print("✓ AESMainWindow created")
    
    window.show()
    print("✓ Window shown")
    
    # Close window after 2 seconds
    QTimer.singleShot(2000, app.quit)
    print("✓ Timer set to close window")
    
    result = app.exec_()
    print(f"✓ GUI launched and closed successfully (exit code: {result})")
    
except Exception as e:
    print(f"✗ GUI launch failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("✅ AES GUI launch test completed successfully!")