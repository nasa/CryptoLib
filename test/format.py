"""
RUN THIS FILE FROM THE REPO ROOT DIRECTORY!
"""


import os
import subprocess
import pathspec

def load_gitignore_patterns(gitignore_path):
    """
    Loads patterns from a .gitignore file.
    
    :param gitignore_path: Path to the .gitignore file.
    :return: A pathspec.PathSpec object containing the patterns from .gitignore.
    """
    with open(gitignore_path, 'r') as file:
        patterns = file.readlines()
    return pathspec.PathSpec.from_lines('gitwildmatch', patterns)

def should_ignore(file_path, gitignore_spec):
    """
    Checks if a file should be ignored based on .gitignore patterns.
    
    :param file_path: The path to the file.
    :param gitignore_spec: The PathSpec object with .gitignore patterns.
    :return: True if the file should be ignored, False otherwise.
    """
    return gitignore_spec.match_file(file_path)

def format_files(directory):
    """
    Recursively formats all .c and .h files in the given directory using clang-format,
    ignoring any files listed in the .gitignore.
    
    :param directory: The root directory to start searching for files.
    """
    # Load .gitignore patterns if the .gitignore file exists
    gitignore_path = os.path.join(directory, '.gitignore')
    gitignore_spec = load_gitignore_patterns(gitignore_path) if os.path.exists(gitignore_path) else None
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.h')):
                file_path = os.path.relpath(os.path.join(root, file), directory)
                
                # Check if the file is ignored by .gitignore
                if gitignore_spec and should_ignore(file_path, gitignore_spec):
                    print(f"Ignored: {file_path}")
                    continue

                try:
                    # Run clang-format on the file
                    subprocess.run(["clang-format", "-i", "--style=file", os.path.join(directory, file_path)], check=True)
                    print(f"Formatted: {file_path}")
                except subprocess.CalledProcessError as e:
                    print(f"Failed to format {file_path}: {e}")

if __name__ == "__main__":
    # Get the current working directory
    current_directory = os.getcwd()
    
    # Run the formatting process
    format_files(current_directory)
