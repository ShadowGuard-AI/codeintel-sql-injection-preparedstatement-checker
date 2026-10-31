![Banner](banner.png)

# codeintel-SQL-Injection-PreparedStatement-Checker
Identifies locations where string concatenation is used to build SQL queries instead of using prepared statements, highlighting potential SQL injection vulnerabilities. Employs AST parsing to analyze SQL query construction. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-sql-injection-preparedstatement-checker`

## Usage
`./codeintel-sql-injection-preparedstatement-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--ignore`: List of functions/methods to ignore during analysis (e.g., 
- `--log-level`: No description provided

## What is checked and what a clean result means
SQL built with `+`, an f-string with formatted values, `%` formatting, or a `.format` call is checked both on assignment lines and in arguments passed straight to a call such as `execute(...)`. The line "No potential SQL injection vulnerabilities found." is printed only for a file that was read and parsed. A file that cannot be read or parsed exits 1 and never prints that line.

## License
Copyright (c) ShadowStrikeHQ
