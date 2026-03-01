# sentinel/parser.py

import os
from tree_sitter import Parser
from tree_sitter_language_pack import get_language

def parse_powershell(script_content: str) -> tuple[dict | None, str | None]:
    """
    Parses a PowerShell script and returns a standardized AST.

    Args:
        script_content: The PowerShell script content as a string.

    Returns:
        A tuple containing the AST as a dictionary or None, and an error message or None.
    """
    try:
        ps_lang = get_language('powershell')
        parser = Parser()
        
        parser.language = ps_lang

        tree = parser.parse(bytes(script_content, "utf8"))
        root_node = tree.root_node

        # Tree-sitter is error-tolerant and may mark has_error=True for minor issues
        # Only reject if there are actual ERROR nodes that indicate significant syntax problems
        def find_error_nodes(node):
            """Recursively find all ERROR nodes in the tree."""
            errors = []
            if node.type == 'ERROR':
                errors.append(node)
            for child in node.children:
                errors.extend(find_error_nodes(child))
            return errors
        
        error_nodes = find_error_nodes(root_node)
        
        # Only reject if we have significant errors (ERROR nodes with substantial content)
        # Ignore minor parsing issues like unrecognized multipliers (KB, MB, GB)
        # Increased threshold to 200 bytes to be more lenient with PowerShell 7+ syntax (e.g., -Parallel)
        # Script-Sentinel is pattern-based, so perfect AST parsing is not critical
        significant_errors = [
            err for err in error_nodes
            if err.text and len(err.text) > 200  # Ignore ERROR nodes < 200 bytes (likely minor grammar issues)
        ]
        
        if significant_errors:
            first_error = significant_errors[0]
            error_text = first_error.text[:50].decode('utf-8', errors='replace') if first_error.text else ''
            return None, f"Syntax error at line {first_error.start_point[0] + 1}: {error_text}"

        ast = _convert_node_to_dict(root_node)
        return ast, None

    except Exception as e:
        return None, f"An unexpected error occurred during parsing: {e}"

def parse_bash(script_content: str) -> tuple[dict | None, str | None]:
    """
    Parses a Bash script and returns a standardized AST.

    Args:
        script_content: The Bash script content as a string.

    Returns:
        A tuple containing the AST as a dictionary or None, and an error message or None.
    """
    try:
        bash_lang = get_language('bash')
        parser = Parser()
        
        parser.language = bash_lang

        tree = parser.parse(bytes(script_content, "utf8"))
        root_node = tree.root_node

        # Tree-sitter is error-tolerant and may mark has_error=True for minor issues
        # Only reject if there are actual ERROR nodes that indicate significant syntax problems
        def find_error_nodes(node):
            """Recursively find all ERROR nodes in the tree."""
            errors = []
            if node.type == 'ERROR':
                errors.append(node)
            for child in node.children:
                errors.extend(find_error_nodes(child))
            return errors
        
        error_nodes = find_error_nodes(root_node)
        
        # Only reject if we have significant errors (ERROR nodes with substantial content)
        # Ignore minor parsing issues
        # Increased threshold for consistency with PowerShell parser
        significant_errors = [
            err for err in error_nodes
            if err.text and len(err.text) > 200  # Ignore ERROR nodes < 200 bytes (likely minor grammar issues)
        ]
        
        if significant_errors:
            first_error = significant_errors[0]
            error_text = first_error.text[:50].decode('utf-8', errors='replace') if first_error.text else ''
            return None, f"Syntax error at line {first_error.start_point[0] + 1}: {error_text}"

        ast = _convert_node_to_dict(root_node)
        return ast, None

    except Exception as e:
        return None, f"An unexpected error occurred during parsing: {e}"

def parse_javascript(script_content: str) -> tuple[dict | None, str | None]:
    """
    Parses a JavaScript script and returns a standardized AST.

    Args:
        script_content: The JavaScript script content as a string.

    Returns:
        A tuple containing the AST as a dictionary or None, and an error message or None.
    """
    try:
        js_lang = get_language('javascript')
        parser = Parser()
        
        parser.language = js_lang

        tree = parser.parse(bytes(script_content, "utf8"))
        root_node = tree.root_node

        # Tree-sitter is error-tolerant and may mark has_error=True for minor issues
        # Only reject if there are actual ERROR nodes that indicate significant syntax problems
        def find_error_nodes(node):
            """Recursively find all ERROR nodes in the tree."""
            errors = []
            if node.type == 'ERROR':
                errors.append(node)
            for child in node.children:
                errors.extend(find_error_nodes(child))
            return errors
        
        error_nodes = find_error_nodes(root_node)
        
        # Only reject if we have significant errors (ERROR nodes with substantial content)
        # Ignore minor parsing issues
        # Increased threshold for consistency with PowerShell parser
        significant_errors = [
            err for err in error_nodes
            if err.text and len(err.text) > 200  # Ignore ERROR nodes < 200 bytes (likely minor grammar issues)
        ]
        
        if significant_errors:
            first_error = significant_errors[0]
            error_text = first_error.text[:50].decode('utf-8', errors='replace') if first_error.text else ''
            return None, f"Syntax error at line {first_error.start_point[0] + 1}: {error_text}"

        ast = _convert_node_to_dict(root_node)
        return ast, None

    except Exception as e:
        return None, f"An unexpected error occurred during parsing: {e}"

def _convert_node_to_dict(node) -> dict:
    """
    Recursively converts a tree-sitter Node to a dictionary.
    """
    return {
        'type': node.type,
        'start_position': node.start_point,
        'end_position': node.end_point,
        'children': [_convert_node_to_dict(child) for child in node.children]
    }

def parse(script_content: str, language: str) -> tuple[dict | None, str | None]:
    """
    Parses a script based on its language and returns a standardized AST.
    """
    if language.lower() == 'powershell':
        return parse_powershell(script_content)
    elif language.lower() == 'bash':
        return parse_bash(script_content)
    elif language.lower() == 'javascript':
        return parse_javascript(script_content)
    else:
        return None, f"Unsupported language: {language}"
