# Makefile for AES System

# Python settings
PYTHON = python3
PIP = pip3

# Directories
PYTHON_DIR = python
FPGA_DIR = fpga
GUI_DIR = gui
BUILD_DIR = build
DIST_DIR = dist

# Source files
AES_CORE = $(PYTHON_DIR)/aes_core.py
FILE_CRYPTO = $(PYTHON_DIR)/file_crypto.py
AES_GUI = $(GUI_DIR)/aes_gui.py

# FPGA files
FPGA_SOURCE = $(FPGA_DIR)/aes_accelerator.v

# Install requirements
requirements:
	$(PIP) install PyQt5 numpy

# Run AES GUI
gui: $(AES_GUI)
	cd $(GUI_DIR) && $(PYTHON) aes_gui.py

# Run AES core tests
test: $(AES_CORE)
	$(PYTHON) -c "from python.aes_core import AES; print('AES core import successful')"

# FPGA synthesis (requires Vivado/Quartus)
fpga: $(FPGA_SOURCE)
	@echo "FPGA synthesis requires Vivado or Quartus"
	@echo "Add synthesis scripts for your FPGA tool"

# Create distribution
dist:
	$(PYTHON) -m build

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	rm -rf __pycache__ $(PYTHON_DIR)/__pycache__
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# Help
help:
	@echo "AES System Build System"
	@echo "====================="
	@echo "Available targets:"
	@echo "  requirements - Install Python dependencies"
	@echo "  gui          - Run AES GUI application"
	@echo "  test         - Test AES core import"
	@echo "  fpga         - FPGA synthesis (requires tools)"
	@echo "  dist         - Create distribution package"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"

.PHONY: requirements gui test fpga dist clean help
