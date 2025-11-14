"""
HTML utilities for fixing display issues in Streamlit
"""

import html
import re
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


def decode_html_entities(text):
    """
    Decode HTML entities in text to fix display issues.
    
    Args:
        text: String that may contain HTML entities
        
    Returns:
        String with HTML entities decoded
    """
    if not isinstance(text, str):
        return text
    
    # Decode common HTML entities
    text = html.unescape(text)
    
    # Additional manual fixes for common cases that might not be caught
    replacements = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#39;': "'",
        '&nbsp;': ' ',
        '&ndash;': '–',
        '&mdash;': '—',
        '&hellip;': '…',
        '&copy;': '©',
        '&reg;': '®',
        '&trade;': '™'
    }
    
    for entity, replacement in replacements.items():
        text = text.replace(entity, replacement)
    
    return text


def clean_display_text(text):
    """
    Clean text for better display in Streamlit.
    
    Args:
        text: String to clean
        
    Returns:
        Cleaned string
    """
    if not isinstance(text, str):
        return text
    
    # Decode HTML entities
    text = decode_html_entities(text)
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text


def strip_html_tags(text):
    """
    Remove HTML tags from text and convert to plain text.
    
    Args:
        text: String that may contain HTML tags
        
    Returns:
        Plain text string with HTML tags removed
    """
    if not isinstance(text, str):
        return text
    
    try:
        # Use BeautifulSoup to parse and extract text
        soup = BeautifulSoup(text, 'html.parser')
        return soup.get_text(separator='\n', strip=True)
    except Exception:
        # Fallback to regex if BeautifulSoup fails
        return re.sub(r'<[^<]+?>', '', text)


def clean_html_content(text):
    """
    Clean HTML content by removing tags and fixing entities.
    
    Args:
        text: String that may contain HTML
        
    Returns:
        Clean plain text string
    """
    if not isinstance(text, str):
        return text
    
    # First strip HTML tags
    text = strip_html_tags(text)
    
    # Then decode HTML entities
    text = decode_html_entities(text)
    
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text


def fix_dict_html_entities(data):
    """
    Recursively fix HTML entities in dictionary values.
    
    Args:
        data: Dictionary or other data structure
        
    Returns:
        Data with HTML entities fixed
    """
    if isinstance(data, dict):
        return {key: fix_dict_html_entities(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [fix_dict_html_entities(item) for item in data]
    elif isinstance(data, str):
        return decode_html_entities(data)
    else:
        return data


def clean_dict_html_content(data):
    """
    Recursively clean HTML content in dictionary values.
    
    Args:
        data: Dictionary or other data structure
        
    Returns:
        Data with HTML content cleaned
    """
    if isinstance(data, dict):
        return {key: clean_dict_html_content(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [clean_dict_html_content(item) for item in data]
    elif isinstance(data, str):
        return decode_html_entities(data)
    else:
        return data