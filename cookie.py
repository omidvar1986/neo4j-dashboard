"""
Cookie management for admin API authentication
"""
import logging

logger = logging.getLogger('dashboard')

def get_cookie():
    """
    Get cookies for authentication.
    This function should return a list of cookie strings in the format:
    ['sessionid=value1', 'csrftoken=value2', ...]
    """
    # Try to read from cookies.txt file first
    try:
        with open('cookies.txt', 'r') as f:
            content = f.read().strip()
            if content:
                logger.info("Found cookies in cookies.txt file")
                # Handle both single line and multi-line formats
                if '\n' in content:
                    # Filter out comments and empty lines, only return actual cookie lines
                    cookies = []
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            cookies.append(line)
                    return cookies
                else:
                    # Single line format - split by semicolon
                    return [cookie.strip() for cookie in content.split(';') if cookie.strip() and not cookie.strip().startswith('#')]
    except FileNotFoundError:
        logger.info("No cookies.txt file found")
    except Exception as e:
        logger.error(f"Error reading cookies.txt: {e}")
    
    # Try environment variables
    import os
    sessionid = os.getenv('SESSIONID')
    csrftoken = os.getenv('CSRFTOKEN')
    if sessionid and csrftoken:
        logger.info("Found cookies in environment variables")
        return [f'sessionid={sessionid}', f'csrftoken={csrftoken}']
    
    logger.warning("No cookies found - you need to provide cookies")
    return []

def get_cookie_from_input(session_data):
    """
    Extract cookies from user input (session ID, cookie string, etc.)
    """
    if not session_data:
        return []
    
    # Handle different input formats
    if ';' in session_data:
        # Cookie string format: "sessionid=abc123; csrftoken=xyz789"
        cookies = []
        for cookie in session_data.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                cookies.append(cookie)
        return cookies
    elif '=' in session_data:
        # Single cookie format: "sessionid=abc123"
        return [session_data.strip()]
    else:
        # Just session ID format: "abc123"
        return [f'sessionid={session_data.strip()}']

def get_cookie_from_curl_file(file_path):
    """
    Read cookies from a curl cookie file
    """
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        cookies = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse Netscape cookie file format
                parts = line.split('\t')
                if len(parts) >= 7:
                    name = parts[5]
                    value = parts[6]
                    cookies.append(f'{name}={value}')
        
        return cookies
    except FileNotFoundError:
        logger.warning(f"Cookie file {file_path} not found")
        return []
    except Exception as e:
        logger.error(f"Error reading cookie file: {e}")
        return []
