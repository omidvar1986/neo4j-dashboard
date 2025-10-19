import fcntl

def safe_read_and_append(filename, text):
    """
    Safely reads the content of a file and appends new text to it
    using an exclusive file lock to prevent race conditions.

    Args:
        filename (str): Path to the file to read and append.
        text (str): Text to append to the file.

    Returns:
        str: The content of the file before the new text was appended.
    """
    with open(filename, 'a+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)  # acquire exclusive lock

        # Move to start to read existing content
        f.seek(0)
        existing_content = f.read()

        # Move to end before writing new text
        f.seek(0, 2)
        f.write(text + '\n')
        f.flush()

        fcntl.flock(f, fcntl.LOCK_UN)  # release lock

    return existing_content


def read_file(filename):
    """
    Reads the entire content of a file.

    Args:
        filename (str): Path to the file to read.

    Returns:
        str: The content of the file, or an empty string if it doesn't exist.
    """
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return ''
    
def clear_file(filename):
    """
    Clears the contents of a file.

    Args:
        filename (str): Path to the file to clear.
    """
    # Open in write mode; this automatically truncates the file
    with open(filename, 'w'):
        pass

def clear_and_write_file(filename, text):
    """
    Clears the contents of a file and writes new text to it.

    Args:
        filename (str): Path to the file to clear and write.
        text (str): Text to write to the cleared file.
    """
    with open(filename, 'w') as f:
        f.write(text)
        f.flush()
