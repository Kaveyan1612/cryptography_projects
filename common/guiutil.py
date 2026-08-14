"""PyQt5 helpers shared by the AES and RSA graphical interfaces."""

import os
import traceback
from typing import Callable, Optional

from PyQt5.QtWidgets import QMessageBox


def show_warning(parent, message: str, title: str = "Error") -> None:
    """Show a warning dialog."""
    QMessageBox.warning(parent, title, message)


def show_error(parent, message: str, title: str = "Error",
               print_traceback: bool = False) -> None:
    """Show an error dialog, optionally dumping the traceback to the console."""
    QMessageBox.critical(parent, title, message)
    if print_traceback:
        traceback.print_exc()


def key_size_from_combo(combo) -> int:
    """Read a key size in bits from a combo box entry such as '256 bits'."""
    return int(combo.currentText().split()[0])


def ensure_directory(parent, path: str) -> bool:
    """Create the directory containing path, reporting failures to the user."""
    directory = os.path.dirname(path)
    if not directory or os.path.exists(directory):
        return True
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        show_warning(parent, f"Cannot create output directory: {str(e)}")
        return False


def validate_file_paths(parent, input_file: str, output_file: str) -> bool:
    """Validate that the input file is readable and the output path is usable."""
    if not input_file or not output_file:
        show_warning(parent, "Please select input and output files")
        return False

    if not os.path.exists(input_file):
        show_warning(parent, f"Input file does not exist: {input_file}")
        return False

    if not os.access(input_file, os.R_OK):
        show_warning(parent, f"Cannot read input file: {input_file}")
        return False

    return ensure_directory(parent, output_file)


def run_with_progress(parent, progress_bar, operation: Callable[[], object],
                      failure_message: str):
    """Run an operation behind an indeterminate progress bar.

    Returns the operation's result, or None when it raised.
    """
    try:
        progress_bar.setVisible(True)
        progress_bar.setRange(0, 0)
        result = operation()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)
        return result
    except Exception as e:
        progress_bar.setVisible(False)
        show_error(parent, f"{failure_message}: {str(e)}")
        return None


def run_file_operation(parent, progress_bar, status_label,
                       operation: Callable[[], object], gerund: str, noun: str,
                       success_message: str) -> None:
    """Run a file crypto operation with progress, status and error reporting."""
    try:
        progress_bar.setVisible(True)
        progress_bar.setRange(0, 0)  # Indeterminate progress
        status_label.setText(f"{gerund}...")

        operation()

        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)
        status_label.setText(f"{noun} complete")

        QMessageBox.information(parent, "Success", success_message)
    except PermissionError as e:
        status_label.setText(f"{noun} failed")
        show_error(parent, f"Permission denied: {str(e)}")
    except FileNotFoundError as e:
        status_label.setText(f"{noun} failed")
        show_error(parent, f"File not found: {str(e)}")
    except OSError as e:
        status_label.setText(f"{noun} failed")
        show_error(parent, f"System error: {str(e)}")
    except Exception as e:
        status_label.setText(f"{noun} failed")
        show_error(parent, f"{noun} failed: {str(e)}", print_traceback=True)
    finally:
        progress_bar.setVisible(False)


def save_text_to_file(parent, path: str, content: str, label: str) -> Optional[bool]:
    """Write text to a file, reporting success or failure to the user."""
    try:
        with open(path, 'w') as f:
            f.write(content)
        QMessageBox.information(parent, "Success", f"{label} exported successfully")
        return True
    except Exception as e:
        show_error(parent, f"Export failed: {str(e)}")
        return False
