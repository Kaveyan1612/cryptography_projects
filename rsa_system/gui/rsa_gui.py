#!/usr/bin/env python3
"""
RSA Cryptography GUI
PyQt5-based graphical interface for RSA operations
"""

import sys
import os
from typing import Tuple
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTextEdit, QComboBox, QGroupBox, QFileDialog,
                             QTabWidget, QSpinBox, QMessageBox, QProgressBar,
                             QSplitter, QCheckBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from python.rsa_core import RSA, RSAKeySize


class RSAKeyPanel(QWidget):
    """Panel for RSA key generation and management"""
    
    def __init__(self):
        super().__init__()
        self.rsa = None
        self.public_key = None
        self.private_key = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Key generation
        key_gen_group = QGroupBox("Key Generation")
        key_gen_layout = QVBoxLayout()
        
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size:"))
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["1024 bits", "2048 bits", "3072 bits", "4096 bits"])
        self.key_size_combo.setCurrentIndex(1)  # Default to 2048
        key_size_layout.addWidget(self.key_size_combo)
        key_gen_layout.addLayout(key_size_layout)
        
        generate_btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Key Pair")
        self.generate_btn.clicked.connect(self.generate_keypair)
        generate_btn_layout.addWidget(self.generate_btn)
        key_gen_layout.addLayout(generate_btn_layout)
        
        self.key_status = QLabel("No keys generated")
        key_gen_layout.addWidget(self.key_status)
        
        key_gen_group.setLayout(key_gen_layout)
        layout.addWidget(key_gen_group)
        
        # Key display
        key_display_group = QGroupBox("Key Information")
        key_display_layout = QVBoxLayout()
        
        self.public_key_display = QTextEdit()
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setMaximumHeight(100)
        self.public_key_display.setPlaceholderText("Public key will appear here...")
        key_display_layout.addWidget(QLabel("Public Key:"))
        key_display_layout.addWidget(self.public_key_display)
        
        self.private_key_display = QTextEdit()
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setMaximumHeight(100)
        self.private_key_display.setPlaceholderText("Private key will appear here...")
        key_display_layout.addWidget(QLabel("Private Key:"))
        key_display_layout.addWidget(self.private_key_display)
        
        key_display_group.setLayout(key_display_layout)
        layout.addWidget(key_display_group)
        
        # Key export
        export_group = QGroupBox("Key Export")
        export_layout = QHBoxLayout()
        
        self.export_public_btn = QPushButton("Export Public Key")
        self.export_public_btn.clicked.connect(self.export_public_key)
        export_layout.addWidget(self.export_public_btn)
        
        self.export_private_btn = QPushButton("Export Private Key")
        self.export_private_btn.clicked.connect(self.export_private_key)
        export_layout.addWidget(self.export_private_btn)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)
        
        self.setLayout(layout)
    
    def generate_keypair(self):
        """Generate RSA key pair"""
        try:
            key_size = int(self.key_size_combo.currentText().split()[0])
            self.rsa = RSA(key_size)
            
            self.key_status.setText("Generating keys...")
            QApplication.processEvents()
            
            self.public_key, self.private_key = self.rsa.generate_keypair()
            
            self.public_key_display.setText(self.rsa.export_public_key(self.public_key))
            self.private_key_display.setText(self.rsa.export_private_key())
            
            key_info = self.rsa.get_key_info()
            self.key_status.setText(f"Keys generated! Modulus: {key_info['modulus_bits']} bits")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {str(e)}")
            self.key_status.setText("Key generation failed")
    
    def export_public_key(self):
        """Export public key to file"""
        if not self.public_key:
            QMessageBox.warning(self, "Error", "No public key to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, "Export Public Key", "public_key.pem")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.rsa.export_public_key(self.public_key))
                QMessageBox.information(self, "Success", "Public key exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def export_private_key(self):
        """Export private key to file"""
        if not self.private_key:
            QMessageBox.warning(self, "Error", "No private key to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(self, "Export Private Key", "private_key.pem")
        if filename:
            try:
                # Private key material must not be readable by other users
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(self.rsa.export_private_key())
                QMessageBox.information(self, "Success", "Private key exported successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def is_ready(self) -> bool:
        """Check if keys are ready"""
        return self.rsa is not None and self.public_key is not None and self.private_key is not None


class RSAEncryptionPanel(QWidget):
    """Panel for RSA encryption/decryption"""
    
    def __init__(self, key_panel: RSAKeyPanel):
        super().__init__()
        self.key_panel = key_panel
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Input
        input_group = QGroupBox("Input Data")
        input_layout = QVBoxLayout()
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to encrypt/decrypt...")
        input_layout.addWidget(self.input_text)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_data)
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_data)
        button_layout.addWidget(self.encrypt_btn)
        button_layout.addWidget(self.decrypt_btn)
        layout.addLayout(button_layout)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Result will appear here...")
        output_layout.addWidget(self.output_text)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        self.setLayout(layout)
    
    def encrypt_data(self):
        """Encrypt data"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        text = self.input_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to encrypt")
            return
        
        try:
            data = text.encode('utf-8')
            encrypted = self.key_panel.rsa.encrypt_bytes(data, self.key_panel.public_key)
            
            result = f"Encrypted data (hex):\n{encrypted.hex()}\n\n"
            result += f"Data length: {len(encrypted)} bytes"
            
            self.output_text.setText(result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
    
    def decrypt_data(self):
        """Decrypt data"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        hex_text = self.input_text.toPlainText().strip()
        if not hex_text:
            QMessageBox.warning(self, "Error", "Please enter hex data to decrypt")
            return
        
        try:
            data = bytes.fromhex(hex_text)
            decrypted = self.key_panel.rsa.decrypt_bytes(data, self.key_panel.private_key)
            
            result = f"Decrypted data:\n{decrypted.decode('utf-8')}\n\n"
            result += f"Data length: {len(decrypted)} bytes"
            
            self.output_text.setText(result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")


class RSASignaturePanel(QWidget):
    """Panel for digital signatures"""
    
    def __init__(self, key_panel: RSAKeyPanel):
        super().__init__()
        self.key_panel = key_panel
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Message input
        message_group = QGroupBox("Message")
        message_layout = QVBoxLayout()
        
        self.message_text = QTextEdit()
        self.message_text.setPlaceholderText("Enter message to sign/verify...")
        message_layout.addWidget(self.message_text)
        
        message_group.setLayout(message_layout)
        layout.addWidget(message_group)
        
        # Signature input
        signature_group = QGroupBox("Signature")
        signature_layout = QVBoxLayout()
        
        self.signature_input = QLineEdit()
        self.signature_input.setPlaceholderText("Enter signature (hex) for verification...")
        signature_layout.addWidget(self.signature_input)
        
        signature_group.setLayout(signature_layout)
        layout.addWidget(signature_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.sign_btn = QPushButton("Sign")
        self.sign_btn.clicked.connect(self.sign_message)
        self.verify_btn = QPushButton("Verify")
        self.verify_btn.clicked.connect(self.verify_signature)
        button_layout.addWidget(self.sign_btn)
        button_layout.addWidget(self.verify_btn)
        layout.addLayout(button_layout)
        
        # Output
        output_group = QGroupBox("Result")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Result will appear here...")
        output_layout.addWidget(self.output_text)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        self.setLayout(layout)
    
    def sign_message(self):
        """Sign message"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        message = self.message_text.toPlainText()
        if not message:
            QMessageBox.warning(self, "Error", "Please enter message to sign")
            return
        
        try:
            signature, hash_algo = self.key_panel.rsa.sign(message, self.key_panel.private_key)
            
            result = f"Signature (hex):\n{signature.hex()}\n\n"
            result += f"Hash Algorithm: {hash_algo}"
            
            self.output_text.setText(result)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Signing failed: {str(e)}")
    
    def verify_signature(self):
        """Verify signature"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        message = self.message_text.toPlainText()
        signature_hex = self.signature_input.text().strip()
        
        if not message or not signature_hex:
            QMessageBox.warning(self, "Error", "Please enter message and signature")
            return
        
        try:
            signature = int(signature_hex, 16)
            is_valid = self.key_panel.rsa.verify(message, signature, self.key_panel.public_key)
            
            if is_valid:
                self.output_text.setText("✓ Signature is VALID")
                self.output_text.setStyleSheet("color: green;")
            else:
                self.output_text.setText("✗ Signature is INVALID")
                self.output_text.setStyleSheet("color: red;")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification failed: {str(e)}")
            self.output_text.setStyleSheet("color: black;")


class RSABenchmarkPanel(QWidget):
    """Panel for RSA benchmarking"""
    
    def __init__(self, key_panel: RSAKeyPanel):
        super().__init__()
        self.key_panel = key_panel
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Benchmark configuration
        config_group = QGroupBox("Benchmark Configuration")
        config_layout = QVBoxLayout()
        
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size:"))
        self.bench_key_size_combo = QComboBox()
        self.bench_key_size_combo.addItems(["1024 bits", "2048 bits", "3072 bits", "4096 bits"])
        self.bench_key_size_combo.setCurrentIndex(1)
        key_size_layout.addWidget(self.bench_key_size_combo)
        config_layout.addLayout(key_size_layout)
        
        iterations_layout = QHBoxLayout()
        iterations_layout.addWidget(QLabel("Iterations:"))
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 1000)
        self.iterations_spin.setValue(10)
        iterations_layout.addWidget(self.iterations_spin)
        config_layout.addLayout(iterations_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Benchmark buttons
        button_layout = QHBoxLayout()
        self.bench_key_gen_btn = QPushButton("Benchmark Key Generation")
        self.bench_key_gen_btn.clicked.connect(self.benchmark_key_generation)
        button_layout.addWidget(self.bench_key_gen_btn)
        
        self.bench_encrypt_btn = QPushButton("Benchmark Encryption")
        self.bench_encrypt_btn.clicked.connect(self.benchmark_encryption)
        button_layout.addWidget(self.bench_encrypt_btn)
        
        self.bench_decrypt_btn = QPushButton("Benchmark Decryption")
        self.bench_decrypt_btn.clicked.connect(self.benchmark_decryption)
        button_layout.addWidget(self.bench_decrypt_btn)
        
        layout.addLayout(button_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results
        results_group = QGroupBox("Benchmark Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("Benchmark results will appear here...")
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        self.setLayout(layout)
    
    def benchmark_key_generation(self):
        """Benchmark key generation"""
        try:
            from python.rsa_core import RSABenchmark
            
            key_size = int(self.bench_key_size_combo.currentText().split()[0])
            iterations = self.iterations_spin.value()
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            results = RSABenchmark.benchmark_key_generation(key_size, iterations)
            
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            
            result_text = f"Key Generation Benchmark ({key_size} bits)\n"
            result_text += f"Iterations: {iterations}\n"
            result_text += f"Average Time: {results['average_time']:.4f}s\n"
            result_text += f"Min Time: {results['min_time']:.4f}s\n"
            result_text += f"Max Time: {results['max_time']:.4f}s\n"
            result_text += f"Total Time: {results['total_time']:.4f}s\n"
            
            self.results_text.setText(result_text)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Error", f"Benchmark failed: {str(e)}")
    
    def benchmark_encryption(self):
        """Benchmark encryption"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        try:
            from python.rsa_core import RSABenchmark
            
            message_size = 32  # 32 bytes
            iterations = self.iterations_spin.value()
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            results = RSABenchmark.benchmark_encryption(self.key_panel.rsa, message_size, iterations)
            
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            
            result_text = f"Encryption Benchmark ({message_size} bytes)\n"
            result_text += f"Iterations: {iterations}\n"
            result_text += f"Average Time: {results['average_time']:.6f}s\n"
            result_text += f"Min Time: {results['min_time']:.6f}s\n"
            result_text += f"Max Time: {results['max_time']:.6f}s\n"
            result_text += f"Total Time: {results['total_time']:.6f}s\n"
            
            self.results_text.setText(result_text)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Error", f"Benchmark failed: {str(e)}")
    
    def benchmark_decryption(self):
        """Benchmark decryption"""
        if not self.key_panel.is_ready():
            QMessageBox.warning(self, "Error", "Please generate key pair first")
            return
        
        try:
            from python.rsa_core import RSABenchmark
            
            message_size = 32  # 32 bytes
            iterations = self.iterations_spin.value()
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            
            results = RSABenchmark.benchmark_decryption(self.key_panel.rsa, message_size, iterations)
            
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            
            result_text = f"Decryption Benchmark ({message_size} bytes)\n"
            result_text += f"Iterations: {iterations}\n"
            result_text += f"Average Time: {results['average_time']:.6f}s\n"
            result_text += f"Min Time: {results['min_time']:.6f}s\n"
            result_text += f"Max Time: {results['max_time']:.6f}s\n"
            result_text += f"Total Time: {results['total_time']:.6f}s\n"
            
            self.results_text.setText(result_text)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Error", f"Benchmark failed: {str(e)}")


class RSAMainWindow(QMainWindow):
    """Main RSA application window"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        self.setWindowTitle("RSA Cryptography System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        
        # Key panel
        self.key_panel = RSAKeyPanel()
        self.key_panel.setMaximumWidth(400)
        
        # Tab widget for different operations
        tab_widget = QTabWidget()
        
        # Encryption panel
        self.encryption_panel = RSAEncryptionPanel(self.key_panel)
        tab_widget.addTab(self.encryption_panel, "Encryption/Decryption")
        
        # Signature panel
        self.signature_panel = RSASignaturePanel(self.key_panel)
        tab_widget.addTab(self.signature_panel, "Digital Signatures")
        
        # Benchmark panel
        self.benchmark_panel = RSABenchmarkPanel(self.key_panel)
        tab_widget.addTab(self.benchmark_panel, "Benchmarking")
        
        # Add widgets to main layout
        main_layout.addWidget(self.key_panel)
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
        QMessageBox.about(self, "About RSA System",
                          "RSA Cryptography System\n"
                          "Complete RSA implementation with key generation\n"
                          "Python/C++ Implementation\n\n"
                          "Features:\n"
                          "- Variable key size (1024-4096 bits)\n"
                          "- Encryption/decryption\n"
                          "- Digital signatures\n"
                          "- Key exchange\n"
                          "- Performance benchmarking\n\n"
                          "Version 1.0")


def main():
    """Main function"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = RSAMainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()