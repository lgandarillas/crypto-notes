"""
src/ui_utils.py
This module provides utility functions for the user interface.
"""

from time import sleep
from progress.bar import Bar

def show_progress_bar(task_description="Processing... ", duration=2.0):
	"""Show a progress bar with a given task description and duration."""
	with Bar(task_description, max=100) as bar:
		for i in range(100):
			sleep(duration / 100)
			bar.next()
