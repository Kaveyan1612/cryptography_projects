#!/usr/bin/env python3
"""
AES Encryption/Decryption GUI
PyQt5-based graphical interface for AES operations
"""

import logging
import sys
import os
import traceback
from typing import Tuple
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTextEdit, QComboBox, QGroupBox, QFileDialog,
                             QTabWidget, QSpinBox, QCheckBox, QMessageBox,
                             QProgressBar, QSplitter)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Add python directory to path
python_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
if python_dir not in sys.path:
    sys.path.insert(0, python_dir)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

try:
    from aes_core import AES, AESMode
    from file_crypto import FileCrypto
    from aes_core_simple import SimpleAESMode
except ImportError as e:
    logger.critical("Failed to import the AES implementation: %s", e)
    sys.exit(1)


class AESControlPanel(QWidget):
    """Control panel for AES configuration"""
    
    def __init__(self):
        super().__init__()
        self.key = None
        self.iv = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Key configuration
        key_group = QGroupBox("Key Configuration")
        key_layout = QVBoxLayout()
        
        # Key size selection
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size:"))
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["128 bits", "192 bits", "256 bits"])
        self.key_size_combo.setCurrentIndex(2)  # Default to 256
        key_size_layout.addWidget(self.key_size_combo)
        key_layout.addLayout(key_size_layout)
        
        # Key generation
        key_gen_layout = QHBoxLayout()
        self.generate_key_btn = QPushButton("Generate Key")
        self.generate_key_btn.clicked.connect(self.generate_key)
        key_gen_layout.addWidget(self.generate_key_btn)
        key_layout.addLayout(key_gen_layout)
        
        # Key display
        key_display_layout = QHBoxLayout()
        key_display_layout.addWidget(QLabel("Key (hex):"))
        self.key_display = QLineEdit()
        self.key_display.setReadOnly(True)
        self.key_display.setPlaceholderText("No key generated")
        key_display_layout.addWidget(self.key_display)
        key_layout.addLayout(key_display_layout)
        
        # Key input
        key_input_layout = QHBoxLayout()
        key_input_layout.addWidget(QLabel("Or enter key:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter hex key")
        self.key_input.textChanged.connect(self.validate_key)
        key_input_layout.addWidget(self.key_input)
        key_layout.addLayout(key_input_layout)
        
        key_group.setLayout(key_layout)
        layout.addWidget(key_group)
        
        # Mode configuration
        mode_group = QGroupBox("Mode Configuration")
        mode_layout = QVBoxLayout()
        
        mode_select_layout = QHBoxLayout()
        mode_select_layout.addWidget(QLabel("AES Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CBC", "CFB", "OFB", "CTR"])
        self.mode_combo.setCurrentIndex(1)  # Default to CBC
        mode_select_layout.addWidget(self.mode_combo)
        mode_layout.addLayout(mode_select_layout)
        
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # IV configuration
        iv_group = QGroupBox("IV Configuration")
        iv_layout = QVBoxLayout()
        
        iv_gen_layout = QHBoxLayout()
        self.generate_iv_btn = QPushButton("Generate IV")
        self.generate_iv_btn.clicked.connect(self.generate_iv)
        iv_gen_layout.addWidget(self.generate_iv_btn)
        iv_layout.addLayout(iv_gen_layout)
        
        iv_display_layout = QHBoxLayout()
        iv_display_layout.addWidget(QLabel("IV (hex):"))
        self.iv_display = QLineEdit()
        self.iv_display.setReadOnly(True)
        self.iv_display.setPlaceholderText("No IV generated")
        iv_display_layout.addWidget(self.iv_display)
        iv_layout.addLayout(iv_display_layout)
        
        iv_group.setLayout(iv_layout)
        layout.addWidget(iv_group)
        
        # Status
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: green;")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def _set_status(self, message: str, is_error: bool = False):
        """Update the status label, colour-coded by severity"""
        self.status_label.setStyleSheet("color: red;" if is_error else "color: green;")
        self.status_label.setText(message)
    
    def generate_key(self):
        """Generate random AES key"""
        try:
            key_size = int(self.key_size_combo.currentText().split()[0])
            self.key = FileCrypto.generate_key(key_size)
        except Exception as e:
            logger.exception("Key generation failed")
            self.key = None
            self.key_display.clear()
            self._set_status("Key generation failed", is_error=True)
            QMessageBox.critical(self, "Error", f"Key generation failed: {e}")
            return
        
        self.key_display.setText(FileCrypto.key_to_hex(self.key))
        self._set_status(f"Generated {key_size}-bit key")
    
    def generate_iv(self):
        """Generate random IV"""
        try:
            self.iv = FileCrypto.generate_iv()
        except Exception as e:
            logger.exception("IV generation failed")
            self.iv = None
            self.iv_display.clear()
            self._set_status("IV generation failed", is_error=True)
            QMessageBox.critical(self, "Error", f"IV generation failed: {e}")
            return
        
        self.iv_display.setText(FileCrypto.key_to_hex(self.iv))
        self._set_status("Generated IV")
    
    def validate_key(self):
        """Validate entered key"""
        hex_string = self.key_input.text().strip()
        if not hex_string:
            self.key = None
            self._set_status("Waiting for a key", is_error=True)
            return
        
        try:
            key = FileCrypto.hex_to_key(hex_string)
        except ValueError as e:
            self.key = None
            self._set_status(f"Invalid hex key: {e}", is_error=True)
            return
        
        if len(key) * 8 not in [128, 192, 256]:
            self.key = None
            self._set_status(
                f"Key must be 128, 192 or 256 bits (got {len(key) * 8})", is_error=True
            )
            return
        
        self.key = key
        self._set_status("Key loaded from input")
    
    def get_aes_mode(self) -> AESMode:
        """Get selected AES mode"""
        mode_text = self.mode_combo.currentText()
        return {
            "ECB": AESMode.ECB,
            "CBC": AESMode.CBC,
            "CFB": AESMode.CFB,
            "OFB": AESMode.OFB,
            "CTR": AESMode.CTR
        }[mode_text]
    
    def is_ready(self) -> bool:
        """Check if configuration is ready"""
        if self.key is None:
            return False
        
        mode = self.get_aes_mode()
        if mode != AESMode.ECB and self.iv is None:
            return False
        
        return True


class TextCryptoPanel(QWidget):
    """Panel for text encryption/decryption"""
    
    def __init__(self, control_panel: AESControlPanel):
        super().__init__()
        self.control_panel = control_panel
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Input text
        input_group = QGroupBox("Input Text")
        input_layout = QVBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to encrypt/decrypt...")
        input_layout.addWidget(self.input_text)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_text)
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_text)
        button_layout.addWidget(self.encrypt_btn)
        button_layout.addWidget(self.decrypt_btn)
        layout.addLayout(button_layout)
        
        # Output text
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Result will appear here...")
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        self.setLayout(layout)
    
    def encrypt_text(self):
        """Encrypt text"""
        try:
            if not self.control_panel.is_ready():
                QMessageBox.warning(self, "Error", "Please configure key and IV first")
                return
            
            text = self.input_text.toPlainText()
            if not text:
                QMessageBox.warning(self, "Error", "Please enter text to encrypt")
                return
            
            mode = self.control_panel.get_aes_mode()
            ciphertext, iv = FileCrypto.encrypt_text(text, self.control_panel.key, mode)
            
            # Update IV if generated
            if iv and self.control_panel.iv is None:
                self.control_panel.iv = iv
                self.control_panel.iv_display.setText(FileCrypto.key_to_hex(iv))
            
            # Display result in a format that's easy to copy-paste for decryption
            result = f"Ciphertext (hex):\n{ciphertext.hex()}\n\n"
            if iv:
                result += f"IV (hex):\n{iv.hex()}"
            else:
                result += "IV: Not required for ECB mode"
            
            self.output_text.setText(result)
            
        except Exception as e:
            logger.exception("Text encryption failed")
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt text with improved copy-paste handling"""
        try:
            if not self.control_panel.is_ready():
                QMessageBox.warning(self, "Error", "Please configure key and IV first")
                return
            
            hex_text = self.input_text.toPlainText().strip()
            if not hex_text:
                QMessageBox.warning(self, "Error", "Please enter hex ciphertext to decrypt")
                return
            
            # Handle various input formats
            ciphertext_hex = None
            iv_hex = None
            
            # Case 1: Full GUI format with both ciphertext and IV
            if "Ciphertext (hex):" in hex_text and "IV (hex):" in hex_text:
                parts = hex_text.split("IV (hex):")
                ciphertext_part = parts[0].strip()
                iv_part = parts[1].strip()
                
                # Extract hex from ciphertext part
                if "Ciphertext (hex):" in ciphertext_part:
                    ciphertext_hex = ciphertext_part.split("Ciphertext (hex):")[1].strip()
                else:
                    ciphertext_hex = ciphertext_part.strip()
                
                iv_hex = iv_part.strip()
            
            # Case 2: Only ciphertext (use current IV)
            elif "Ciphertext (hex):" in hex_text:
                ciphertext_hex = hex_text.split("Ciphertext (hex):")[1].strip()
                iv_hex = None  # Will use current IV
            
            # Case 3: Raw hex string (no labels)
            else:
                ciphertext_hex = hex_text
                iv_hex = None  # Will use current IV
            
            # Clean up hex strings
            if ciphertext_hex:
                ciphertext_hex = ciphertext_hex.strip()
                # Remove any remaining labels or whitespace
                if "IV" in ciphertext_hex:
                    ciphertext_hex = ciphertext_hex.split("IV")[0].strip()
            
            if iv_hex:
                iv_hex = iv_hex.strip()
            
            # Validate we have ciphertext
            if not ciphertext_hex:
                QMessageBox.warning(self, "Error", "No valid ciphertext found in input")
                return
            
            # Convert hex to bytes with improved error handling
            try:
                ciphertext = FileCrypto.hex_to_key(ciphertext_hex)
            except ValueError as e:
                QMessageBox.warning(self, "Error", f"Invalid hex format in ciphertext: {str(e)}")
                return
            
            # Handle IV
            iv = None
            if iv_hex:
                try:
                    iv = FileCrypto.hex_to_key(iv_hex)
                except ValueError as e:
                    QMessageBox.warning(self, "Error", f"Invalid hex format in IV: {str(e)}")
                    return
            else:
                # Use current IV from control panel
                iv = self.control_panel.iv
            
            mode = self.control_panel.get_aes_mode()
            
            # Ensure IV is set for modes that require it
            if mode != AESMode.ECB and iv is None:
                QMessageBox.warning(self, "Error", f"IV is required for {mode.name} mode. Please configure IV first.")
                return
            
            # Decrypt
            plaintext = FileCrypto.decrypt_text(ciphertext, self.control_panel.key, mode, iv)
            self.output_text.setText(f"Decrypted text:\n{plaintext}")
            
        except Exception as e:
            logger.exception("Text decryption failed")
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")


class FileCryptoPanel(QWidget):
    """Panel for file encryption/decryption"""
    
    def __init__(self, control_panel: AESControlPanel):
        super().__init__()
        self.control_panel = control_panel
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout()
        
        input_file_layout = QHBoxLayout()
        input_file_layout.addWidget(QLabel("Input File:"))
        self.input_file_edit = QLineEdit()
        self.input_file_edit.setReadOnly(True)
        input_file_layout.addWidget(self.input_file_edit)
        self.browse_input_btn = QPushButton("Browse")
        self.browse_input_btn.clicked.connect(self.browse_input_file)
        input_file_layout.addWidget(self.browse_input_btn)
        file_layout.addLayout(input_file_layout)
        
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(QLabel("Output File:"))
        self.output_file_edit = QLineEdit()
        self.output_file_edit.setReadOnly(True)
        output_file_layout.addWidget(self.output_file_edit)
        self.browse_output_btn = QPushButton("Browse")
        self.browse_output_btn.clicked.connect(self.browse_output_file)
        output_file_layout.addWidget(self.browse_output_btn)
        file_layout.addLayout(output_file_layout)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_file_btn = QPushButton("Encrypt File")
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        self.decrypt_file_btn = QPushButton("Decrypt File")
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        button_layout.addWidget(self.encrypt_file_btn)
        button_layout.addWidget(self.decrypt_file_btn)
        layout.addLayout(button_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def browse_input_file(self):
        """Browse for input file with improved error handling"""
        filename, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if not filename:
            return
        
        # Validate file path
        if not os.path.exists(filename):
            QMessageBox.warning(self, "Error", f"Selected file does not exist: {filename}")
            return
        
        self.input_file_edit.setText(filename)
        # Auto-generate output filename
        if not self.output_file_edit.text():
            base, ext = os.path.splitext(filename)
            self.output_file_edit.setText(base + "_encrypted" + ext)
    
    def browse_output_file(self):
        """Browse for output file with improved error handling"""
        filename, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if not filename:
            return
        
        # Validate directory
        output_dir = os.path.dirname(filename)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                logger.exception("Cannot create output directory %s", output_dir)
                QMessageBox.warning(self, "Error", f"Cannot create output directory: {str(e)}")
                return
        
        self.output_file_edit.setText(filename)
    
    def encrypt_file(self):
        """Encrypt file with improved error handling"""
        if not self.control_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please configure key and IV first")
            return
        
        input_file = self.input_file_edit.text()
        output_file = self.output_file_edit.text()
        
        if not input_file or not output_file:
            QMessageBox.warning(self, "Error", "Please select input and output files")
            return
        
        # Validate input file exists
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "Error", f"Input file does not exist: {input_file}")
            return
        
        # Validate input file is readable
        if not os.access(input_file, os.R_OK):
            QMessageBox.warning(self, "Error", f"Cannot read input file: {input_file}")
            return
        
        # Validate output directory exists and is writable
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                logger.exception("Cannot create output directory %s", output_dir)
                QMessageBox.warning(self, "Error", f"Cannot create output directory: {str(e)}")
                return
        
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.status_label.setText("Encrypting...")
            
            mode = self.control_panel.get_aes_mode()
            key, iv = FileCrypto.encrypt_file(input_file, output_file, 
                                            self.control_panel.key, mode)
            
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.status_label.setText("Encryption complete")
            
            QMessageBox.information(self, "Success", "File encrypted successfully")
            
        except PermissionError as e:
            logger.exception("File encryption failed: permission denied")
            self.status_label.setText("Encryption failed")
            QMessageBox.critical(self, "Error", f"Permission denied: {str(e)}")
        except FileNotFoundError as e:
            logger.exception("File encryption failed: file not found")
            self.status_label.setText("Encryption failed")
            QMessageBox.critical(self, "Error", f"File not found: {str(e)}")
        except OSError as e:
            logger.exception("File encryption failed: OS error")
            self.status_label.setText("Encryption failed")
            QMessageBox.critical(self, "Error", f"System error: {str(e)}")
        except Exception as e:
            logger.exception("File encryption failed")
            self.status_label.setText("Encryption failed")
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
    
    def decrypt_file(self):
        """Decrypt file with improved error handling"""
        if not self.control_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please configure key and IV first")
            return
        
        input_file = self.input_file_edit.text()
        output_file = self.output_file_edit.text()
        
        if not input_file or not output_file:
            QMessageBox.warning(self, "Error", "Please select input and output files")
            return
        
        # Validate input file exists
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "Error", f"Input file does not exist: {input_file}")
            return
        
        # Validate input file is readable
        if not os.access(input_file, os.R_OK):
            QMessageBox.warning(self, "Error", f"Cannot read input file: {input_file}")
            return
        
        # Validate output directory exists and is writable
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                logger.exception("Cannot create output directory %s", output_dir)
                QMessageBox.warning(self, "Error", f"Cannot create output directory: {str(e)}")
                return
        
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.status_label.setText("Decrypting...")
            
            mode = self.control_panel.get_aes_mode()
            iv = self.control_panel.iv
            FileCrypto.decrypt_file(input_file, output_file, 
                                   self.control_panel.key, mode, iv)
            
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.status_label.setText("Decryption complete")
            
            QMessageBox.information(self, "Success", "File decrypted successfully")
            
        except PermissionError as e:
            logger.exception("File decryption failed: permission denied")
            self.status_label.setText("Decryption failed")
            QMessageBox.critical(self, "Error", f"Permission denied: {str(e)}")
        except FileNotFoundError as e:
            logger.exception("File decryption failed: file not found")
            self.status_label.setText("Decryption failed")
            QMessageBox.critical(self, "Error", f"File not found: {str(e)}")
        except OSError as e:
            logger.exception("File decryption failed: OS error")
            self.status_label.setText("Decryption failed")
            QMessageBox.critical(self, "Error", f"System error: {str(e)}")
        except Exception as e:
            logger.exception("File decryption failed")
            self.status_label.setText("Decryption failed")
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)


class AESMainWindow(QMainWindow):
    """Main AES application window"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("AES Encryption/Decryption System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        
        # Control panel
        self.control_panel = AESControlPanel()
        self.control_panel.setMaximumWidth(400)
        
        # Tab widget for different operations
        tab_widget = QTabWidget()
        
        # Text crypto panel
        self.text_panel = TextCryptoPanel(self.control_panel)
        tab_widget.addTab(self.text_panel, "Text")
        
        # File crypto panel
        self.file_panel = FileCryptoPanel(self.control_panel)
        tab_widget.addTab(self.file_panel, "File")
        
        # Add widgets to main layout
        main_layout.addWidget(self.control_panel)
        main_layout.addWidget(tab_widget)
        
        central_widget.setLayout(main_layout)
        
        # Menu bar
        self.create_menu()
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def create_menu(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = help_menu.addAction('About')
        about_action.triggered.connect(self.show_about)
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About AES System",
                          "AES Encryption/Decryption System\n"
                          "Hardware-accelerated AES-128/192/256\n"
                          "Python/C++/FPGA Implementation\n\n"
                          "Features:\n"
                          "- Multiple AES modes (ECB, CBC, CFB, OFB, CTR)\n"
                          "- Text and file encryption\n"
                          "- FPGA hardware acceleration\n"
                          "- Performance benchmarking\n\n"
                          "Version 1.0")


def _install_exception_hook():
    """Surface unhandled exceptions instead of letting Qt discard them"""
    def hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logger.critical("Unhandled exception",
                        exc_info=(exc_type, exc_value, exc_tb))
        details = ''.join(traceback.format_exception_only(exc_type, exc_value)).strip()
        QMessageBox.critical(None, "Unexpected Error",
                             f"An unexpected error occurred:\n\n{details}")
    
    sys.excepthook = hook


def main():
    """Main function"""
    app = QApplication(sys.argv)
    _install_exception_hook()
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = AESMainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()