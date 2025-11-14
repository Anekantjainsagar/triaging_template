"""
Fix for ThreadPoolExecutor ScriptRunContext warnings in Streamlit applications.

This script provides utilities to suppress warnings and handle context issues
when using ThreadPoolExecutor or other threading libraries with Streamlit.
"""

import warnings
import logging
import threading
from contextlib import contextmanager
from typing import Any, Callable, Optional

# Suppress specific warnings
warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")
warnings.filterwarnings("ignore", message=".*ThreadPoolExecutor.*missing ScriptRunContext.*")

# Configure logging to suppress specific warnings
logging.getLogger("streamlit.runtime.scriptrunner.script_runner").setLevel(logging.ERROR)


@contextmanager
def suppress_streamlit_warnings():
    """Context manager to suppress Streamlit threading warnings."""
    # Store original warning filters
    original_filters = warnings.filters.copy()
    
    try:
        # Add specific filters for Streamlit warnings
        warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")
        warnings.filterwarnings("ignore", message=".*ThreadPoolExecutor.*")
        warnings.filterwarnings("ignore", category=UserWarning, module="streamlit")
        
        yield
    finally:
        # Restore original filters
        warnings.filters = original_filters


def safe_thread_execution(func: Callable, *args, **kwargs) -> Any:
    """
    Execute a function safely in a thread context, suppressing Streamlit warnings.
    
    Args:
        func: Function to execute
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
    
    Returns:
        Result of the function execution
    """
    with suppress_streamlit_warnings():
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log the actual error without the context warnings
            logging.error(f"Error in thread execution: {str(e)}")
            raise


def configure_streamlit_logging():
    """Configure logging to reduce Streamlit noise."""
    # Suppress specific loggers
    loggers_to_suppress = [
        "streamlit.runtime.scriptrunner.script_runner",
        "streamlit.runtime.state",
        "streamlit.runtime.caching",
    ]
    
    for logger_name in loggers_to_suppress:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.ERROR)


def is_main_thread() -> bool:
    """Check if we're running in the main thread."""
    return threading.current_thread() is threading.main_thread()


def setup_streamlit_context_fixes():
    """Setup all context fixes for Streamlit applications."""
    configure_streamlit_logging()
    
    # Apply warning filters
    warnings.filterwarnings("ignore", message=".*missing ScriptRunContext.*")
    warnings.filterwarnings("ignore", message=".*ThreadPoolExecutor.*missing ScriptRunContext.*")
    
    # Set environment variable to suppress warnings
    import os
    os.environ["STREAMLIT_SUPPRESS_WARNINGS"] = "1"


if __name__ == "__main__":
    # Apply fixes when run directly
    setup_streamlit_context_fixes()
    print("✅ Streamlit context fixes applied")