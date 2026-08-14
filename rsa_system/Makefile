# Makefile for RSA System

# Python settings
PYTHON = python3
PIP = pip3

# Directories
PYTHON_DIR = python
GUI_DIR = gui
BUILD_DIR = build
DIST_DIR = dist

# Source files
RSA_CORE = $(PYTHON_DIR)/rsa_core.py
RSA_GUI = $(GUI_DIR)/rsa_gui.py

# Install requirements
requirements:
	$(PIP) install PyQt5 numpy

# Run RSA GUI
gui: $(RSA_GUI)
	cd $(GUI_DIR) && $(PYTHON) rsa_gui.py

# Run RSA core tests
test: $(RSA_CORE)
	$(PYTHON) -c "from python.rsa_core import RSA; print('RSA core import successful')"

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
	@echo "RSA System Build System"
	@echo "====================="
	@echo "Available targets:"
	@echo "  requirements - Install Python dependencies"
	@echo "  gui          - Run RSA GUI application"
	@echo "  test         - Test RSA core import"
	@echo "  dist         - Create distribution package"
	@echo "  clean        - Clean build artifacts"
	@echo "  help         - Show this help message"

.PHONY: requirements gui test dist clean help
