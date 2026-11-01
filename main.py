import argparse
import ast
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Identifies potential SQL injection vulnerabilities by checking for string concatenation in SQL queries."
    )
    parser.add_argument(
        "filepath",
        help="Path to the Python file to analyze.",
    )
    parser.add_argument(
        "--ignore",
        nargs="*",
        help="List of functions/methods to ignore during analysis (e.g., 'my_function').",
        default=[]
    )
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help="Set the logging level (default: INFO)"
    )
    return parser


def check_for_sql_injection(filepath, ignore_list=None):
    """
    Analyzes a Python file for potential SQL injection vulnerabilities by detecting string concatenation in SQL query construction.

    Args:
        filepath (str): The path to the Python file to analyze.
        ignore_list (list, optional): A list of function/method names to ignore. Defaults to None.

    Returns:
        list: A list of tuples, where each tuple contains the line number and the potentially vulnerable code snippet.  Returns an empty list only when the file was parsed and no vulnerabilities were found, and None when the file could not be read or parsed, so a caller can tell an unexamined file apart from a clean one.
    """

    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return None

    # A caller that passes no ignore list gets an empty one. Testing
    # membership in None raised TypeError inside the per node handler
    # below, which swallowed it at debug level, so a direct call with
    # the default silently reported nothing for any file.
    if ignore_list is None:
        ignore_list = []

    vulnerable_lines = []
    try:
        with open(filepath, "r") as f:
            code = f.read()
        tree = ast.parse(code)

        def sql_in_text(text):
            upper = text.upper()
            # I decide a string is SQL when one of these words appears in
            # it at all. A sentence in a comment-like string that says
            # delete is enough, which is why I call these potential only.
            return any(word in upper for word in ("SELECT", "INSERT", "UPDATE", "DELETE"))

        for node in ast.walk(tree):
            # The pattern this tool exists for is usually built on an
            # assignment line (query = "SELECT ..." + name) and only
            # executed later by variable, so call arguments alone miss
            # it. Assignments are checked as well as call arguments,
            # including f-string builds.
            if isinstance(node, ast.Assign):
                for sub_node in ast.walk(node.value):
                    if isinstance(sub_node, ast.BinOp) and isinstance(sub_node.op, ast.Add) and sql_in_text(ast.unparse(sub_node)):
                        vulnerable_lines.append((node.lineno, f"Potential SQL injection vulnerability: {ast.unparse(node.value)}"))
                        break
                    if isinstance(sub_node, ast.JoinedStr) and sql_in_text(ast.unparse(sub_node)) and any(isinstance(v, ast.FormattedValue) for v in sub_node.values):
                        vulnerable_lines.append((node.lineno, f"Potential SQL injection vulnerability: {ast.unparse(node.value)}"))
                        break
            if isinstance(node, (ast.Call, ast.Expr)):
                # Check for function calls or expressions
                try:
                    if isinstance(node, ast.Call):
                        func_name = get_function_name(node.func)
                        if func_name in ignore_list:
                            continue
                        args = node.args
                    elif isinstance(node.value, ast.Call):
                        # The inner call is visited as its own node;
                        # walking it again from here would report
                        # every finding in it twice.
                        continue
                    else:
                        args = [node.value]
                    for arg in args:
                        # The assignment handler above also catches
                        # f-string builds, so a build passed straight
                        # to a call has to be checked for the same
                        # forms here: an f-string with formatted
                        # values, a % format build, and a .format
                        # call, alongside the original + build.
                        for sub_node in ast.walk(arg):
                            is_build = False
                            if isinstance(sub_node, ast.BinOp) and isinstance(sub_node.op, (ast.Add, ast.Mod)):
                                is_build = True
                            elif isinstance(sub_node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in sub_node.values):
                                is_build = True
                            elif isinstance(sub_node, ast.Call) and isinstance(sub_node.func, ast.Attribute) and sub_node.func.attr == "format":
                                is_build = True
                            if is_build and sql_in_text(ast.unparse(sub_node)):
                                vulnerable_lines.append((node.lineno, f"Potential SQL injection vulnerability: {ast.unparse(arg)}"))
                                break
                except Exception as e:
                    logging.debug(f"Error processing node: {node} - {e}") # Increased verbosity, making the exceptions DEBUG log level


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except Exception as e:
        logging.error(f"Error parsing file: {filepath} - {e}")
        return None

    return vulnerable_lines


def get_function_name(node):
    """
    Extracts the name of a function or method call from an AST node.

    Args:
        node (ast.AST): The AST node representing the function or method call.

    Returns:
        str: The name of the function or method, or None if the name cannot be determined.
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        # I return only the last part of a method call, so cursor.execute
        # and anything.execute share one name for the ignore list.
        # Ignoring execute therefore ignores every object's execute.
        return node.attr
    elif isinstance(node, ast.Call): # Added to correctly handle nested calls, such as function(another_function())
        return get_function_name(node.func)
    else:
        return None


def main():
    """
    Main function to execute the SQL injection checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set log level based on command line argument
    logging.getLogger().setLevel(args.log_level)

    # The check function returns an empty list for a missing file,
    # which main used to report as a clean scan with exit 0.
    if not os.path.isfile(args.filepath):
        logging.error(f"File not found: {args.filepath}")
        sys.exit(1)

    if not args.filepath:
        logging.error("Filepath is required.")
        return

    try:
        vulnerable_lines = check_for_sql_injection(args.filepath, args.ignore)

        if vulnerable_lines is None:
            # The file was not read or not parsed. Printing the clean
            # line here would give an unexamined file the same verdict
            # as a file that was parsed and found clean.
            sys.exit(1)

        if vulnerable_lines:
            # I print the findings and return normally, so a file with
            # vulnerable lines and a clean file both exit 0. The printed
            # list is the verdict a caller has to read.
            print("Potential SQL injection vulnerabilities found:")
            for line_number, code_snippet in vulnerable_lines:
                print(f"Line {line_number}: {code_snippet}")
        else:
            print("No potential SQL injection vulnerabilities found.")

    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Example Usage:
    # 1. Run on a specific file: python your_script_name.py example.py
    # 2. Ignore certain functions: python your_script_name.py example.py --ignore my_safe_function another_safe_function
    # 3. Set log level to debug: python your_script_name.py example.py --log-level DEBUG

    # Example Vulnerable Code (save as example.py for testing)
    # def get_user(username):
    #     query = "SELECT * FROM users WHERE username = '" + username + "'" # Vulnerable!
    #     cursor.execute(query)
    #
    # def get_item(item_id):
    #     query = "SELECT * FROM items WHERE id = " + str(item_id) # Vulnerable!
    #     cursor.execute(query)
    #
    # def safe_query(item_id):
    #     query = "SELECT * FROM items WHERE id = ?"
    #     cursor.execute(query, (item_id,))
    #
    #
    # def another_safe_function():
    #     print("Doing safe things")

    # Example Safe Code (save as safe_example.py for testing)
    # def safe_get_user(username):
    #     query = "SELECT * FROM users WHERE username = ?"
    #     cursor.execute(query, (username,))

    # if you remove a filename to analyze the code will error.
    main()