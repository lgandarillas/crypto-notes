"""
src/handle_notes/note_utils.py

Contains utility functions for note handling.
"""

import os
import re

def ensure_directory_exists(directory_path):
	"""Ensures that the specified directory exists, creating it if necessary."""
	if not os.path.exists(directory_path):
		os.makedirs(directory_path)

def validate_note_name(note_name, notes, printer):
	"""Validates the note name and checks if it already exists."""
	if not re.match(r'^\w+$', note_name):
		printer.print_error("Invalid note name. Only letters, numbers, and underscores are allowed.")
		return False

	for note in notes:
		if note["name"] == note_name:
			printer.print_error(f"Note '{note_name}' already exists. Please choose a different name.")
			return False

	return True
