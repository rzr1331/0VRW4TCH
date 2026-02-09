"""
Code Executor Tool.

Execute code in multiple programming languages.
Adapted from CAI's exec_code.py.

Supported languages:
- Python, Bash/Shell
- Ruby, Perl, PHP
- JavaScript (Node.js), TypeScript
- Go, Rust, C, C++, Java, Kotlin, C#
"""

from shared.security_tools.common import run_command


# Language to file extension mapping
LANGUAGE_EXTENSIONS = {
    "python": "py", "py": "py",
    "php": "php",
    "bash": "sh", "shell": "sh", "sh": "sh",
    "ruby": "rb", "rb": "rb",
    "perl": "pl", "pl": "pl",
    "golang": "go", "go": "go",
    "javascript": "js", "js": "js",
    "typescript": "ts", "ts": "ts",
    "rust": "rs", "rs": "rs",
    "csharp": "cs", "cs": "cs",
    "java": "java",
    "kotlin": "kt", "kt": "kt",
    "c": "c",
    "cpp": "cpp", "c++": "cpp",
}

# Language to execution command mapping
LANGUAGE_COMMANDS = {
    "python": "python3",
    "php": "php",
    "bash": "bash", "shell": "bash", "sh": "bash",
    "ruby": "ruby",
    "perl": "perl",
    "javascript": "node", "js": "node",
    "typescript": "ts-node",
}


def execute_code(
    code: str = "",
    language: str = "python",
    filename: str = "script",
    timeout: int = 100,
) -> str:
    """
    Create a file with code, save it, and execute it.
    
    Creates a file with the provided code and executes it using the
    appropriate interpreter. Useful for running exploit scripts,
    automation, or complex remediation tasks.
    
    Args:
        code: The code snippet to execute
        language: Programming language (default: python)
                 Supported: python, bash, shell, ruby, perl, php,
                           javascript, typescript, go, rust, c, cpp, java
        filename: Base name for the file without extension (default: script)
        timeout: Execution timeout in seconds (default: 100)
        
    Returns:
        Command output or error message from execution
        
    Examples:
        - execute_code("print('Hello')", "python")
        - execute_code("echo 'test'", "bash")
        - execute_code("console.log('hi')", "javascript")
    """
    if not code:
        return "Error: No code provided to execute"
    
    # Normalize language
    language = language.lower()
    
    # Get file extension
    ext = LANGUAGE_EXTENSIONS.get(language, "txt")
    if ext == "txt":
        return f"Error: Unsupported language: {language}"
    
    full_filename = f"/tmp/{filename}.{ext}"
    
    # Create code file
    try:
        with open(full_filename, 'w') as f:
            f.write(code)
    except Exception as e:
        return f"Error creating code file: {str(e)}"
    
    # Build execution command based on language
    if language in ["python", "py"]:
        exec_cmd = f"python3 {full_filename}"
    elif language in ["php"]:
        exec_cmd = f"php {full_filename}"
    elif language in ["bash", "sh", "shell"]:
        exec_cmd = f"bash {full_filename}"
    elif language in ["ruby", "rb"]:
        exec_cmd = f"ruby {full_filename}"
    elif language in ["perl", "pl"]:
        exec_cmd = f"perl {full_filename}"
    elif language in ["golang", "go"]:
        exec_cmd = f"go run {full_filename}"
    elif language in ["javascript", "js"]:
        exec_cmd = f"node {full_filename}"
    elif language in ["typescript", "ts"]:
        exec_cmd = f"ts-node {full_filename}"
    elif language in ["rust", "rs"]:
        # Compile then run
        binary = f"/tmp/{filename}"
        compile_result = run_command(f"rustc {full_filename} -o {binary}", timeout=60)
        if "error" in compile_result.lower():
            return f"Rust compilation failed:\n{compile_result}"
        exec_cmd = binary
    elif language in ["c"]:
        binary = f"/tmp/{filename}"
        compile_result = run_command(f"gcc {full_filename} -o {binary}", timeout=60)
        if "error" in compile_result.lower():
            return f"C compilation failed:\n{compile_result}"
        exec_cmd = binary
    elif language in ["cpp", "c++"]:
        binary = f"/tmp/{filename}"
        compile_result = run_command(f"g++ {full_filename} -o {binary}", timeout=60)
        if "error" in compile_result.lower():
            return f"C++ compilation failed:\n{compile_result}"
        exec_cmd = binary
    elif language in ["java"]:
        compile_result = run_command(f"javac {full_filename}", timeout=60)
        if "error" in compile_result.lower():
            return f"Java compilation failed:\n{compile_result}"
        exec_cmd = f"java -cp /tmp {filename}"
    elif language in ["kotlin", "kt"]:
        jar_file = f"/tmp/{filename}.jar"
        compile_result = run_command(
            f"kotlinc {full_filename} -include-runtime -d {jar_file}",
            timeout=120
        )
        if "error" in compile_result.lower():
            return f"Kotlin compilation failed:\n{compile_result}"
        exec_cmd = f"java -jar {jar_file}"
    elif language in ["csharp", "cs"]:
        exec_cmd = f"dotnet run {full_filename}"
    else:
        return f"Error: Unsupported language: {language}"
    
    # Execute the code
    return run_command(exec_cmd, timeout=timeout)
