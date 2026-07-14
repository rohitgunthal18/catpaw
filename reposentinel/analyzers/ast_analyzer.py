"""Python AST-based deep code analysis for RepoSentinel.

Walks the Abstract Syntax Tree to detect dangerous function calls,
imports, and obfuscation chains that regex alone cannot catch.
"""

import ast
from typing import List

from reposentinel.database.severity import Finding


# Dangerous modules and their risk context
DANGEROUS_IMPORTS = {
    "os": ("medium", 35, "T1059.006", "Provides system-level operations"),
    "subprocess": ("high", 60, "T1059", "Enables shell command execution"),
    "socket": ("high", 55, "T1071", "Enables network connections"),
    "ctypes": ("high", 50, "T1055", "Allows direct memory manipulation"),
    "winreg": ("high", 65, "T1547.001", "Windows Registry manipulation"),
    "pickle": ("medium", 45, "T1059.006", "Deserialization can execute code"),
    "marshal": ("high", 60, "T1027.002", "Code object obfuscation"),
    "shutil": ("low", 20, "T1485", "File operations"),
    "paramiko": ("high", 55, "T1021.004", "SSH remote access"),
    "ftplib": ("medium", 45, "T1048", "FTP data transfer"),
    "smtplib": ("medium", 45, "T1048.003", "Email sending"),
    "mss": ("high", 70, "T1113", "Screen capture"),
    "pynput": ("critical", 90, "T1056.001", "Keyboard/mouse input capture"),
    "pyaudio": ("high", 70, "T1123", "Audio recording"),
    "cv2": ("high", 65, "T1125", "Camera/video access"),
}

# Dangerous function calls
DANGEROUS_CALLS = {
    "eval": ("critical", 85, "T1059.006", "Dynamic code execution"),
    "exec": ("critical", 85, "T1059.006", "Dynamic code execution"),
    "compile": ("high", 55, "T1059.006", "Dynamic code compilation"),
    "__import__": ("high", 70, "T1059.006", "Dynamic module import"),
    "getattr": ("medium", 35, "T1059.006", "Dynamic attribute access"),
}


class MaliciousNodeVisitor(ast.NodeVisitor):
    """AST visitor that collects security-relevant patterns."""

    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Finding] = []
        self.imports: List[str] = []
        self.calls: List[str] = []

    def _get_line_content(self, lineno: int) -> str:
        """Get line content safely."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].rstrip('\n\r')[:200]
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        """Check for dangerous module imports."""
        for alias in node.names:
            module_name = alias.name.split('.')[0]
            self.imports.append(module_name)
            if module_name in DANGEROUS_IMPORTS:
                sev, weight, mitre, desc = DANGEROUS_IMPORTS[module_name]
                self.findings.append(Finding(
                    rule_id=f"AST-IMP-{module_name.upper()}",
                    name=f"Dangerous Import: {module_name}",
                    category="execution",
                    subcategory="dangerous_import",
                    severity=sev,
                    weight=weight,
                    description=desc,
                    user_message=f"🔍 This script imports '{module_name}' — {desc.lower()}",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=self._get_line_content(node.lineno),
                    matched_pattern=f"import {module_name}",
                    mitre_attack=mitre,
                    confidence=0.9,
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check for dangerous from...import statements."""
        if node.module:
            module_name = node.module.split('.')[0]
            self.imports.append(module_name)
            if module_name in DANGEROUS_IMPORTS:
                sev, weight, mitre, desc = DANGEROUS_IMPORTS[module_name]
                self.findings.append(Finding(
                    rule_id=f"AST-IMP-{module_name.upper()}",
                    name=f"Dangerous Import: {module_name}",
                    category="execution",
                    subcategory="dangerous_import",
                    severity=sev,
                    weight=weight,
                    description=desc,
                    user_message=f"🔍 This script imports from '{module_name}' — {desc.lower()}",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=self._get_line_content(node.lineno),
                    matched_pattern=f"from {module_name} import ...",
                    mitre_attack=mitre,
                    confidence=0.9,
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check for dangerous function calls and obfuscation chains."""
        func_name = self._get_call_name(node)
        if func_name:
            self.calls.append(func_name)

            # Check for dangerous standalone calls
            base_name = func_name.split('.')[-1]
            if base_name in DANGEROUS_CALLS:
                sev, weight, mitre, desc = DANGEROUS_CALLS[base_name]
                self.findings.append(Finding(
                    rule_id=f"AST-CALL-{base_name.upper()}",
                    name=f"Dangerous Call: {func_name}()",
                    category="execution",
                    subcategory="dangerous_call",
                    severity=sev,
                    weight=weight,
                    description=desc,
                    user_message=f"🔍 Calls {func_name}() — {desc.lower()}",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=self._get_line_content(node.lineno),
                    matched_pattern=f"{func_name}()",
                    mitre_attack=mitre,
                    confidence=0.95,
                ))

            # Check for os.system(), os.popen(), subprocess.Popen(), etc.
            if func_name in ("os.system", "os.popen"):
                self.findings.append(Finding(
                    rule_id="AST-EXEC-OSSYSTEM",
                    name=f"System Command: {func_name}()",
                    category="execution",
                    subcategory="shell_command",
                    severity="high",
                    weight=75,
                    description=f"Executes shell commands via {func_name}",
                    user_message=f"🟠 Calls {func_name}() to run system commands",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    line_content=self._get_line_content(node.lineno),
                    matched_pattern=f"{func_name}()",
                    mitre_attack="T1059",
                    confidence=0.95,
                ))

            # Detect obfuscation chains: exec(base64.b64decode(...))
            self._check_obfuscation_chain(node)

        self.generic_visit(node)

    def _check_obfuscation_chain(self, node: ast.Call) -> None:
        """Detect nested call chains that indicate obfuscation."""
        func_name = self._get_call_name(node)
        if not func_name:
            return

        outer = func_name.split('.')[-1]
        if outer not in ("exec", "eval"):
            return

        # Check if the argument is another function call
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Call):
                inner_name = self._get_call_name(arg)
                if inner_name and any(kw in (inner_name or "").lower() for kw in
                                       ["decode", "b64decode", "decompress", "loads", "fromhex"]):
                    self.findings.append(Finding(
                        rule_id="AST-OBF-CHAIN",
                        name=f"Obfuscation Chain: {outer}({inner_name}(...))",
                        category="obfuscation",
                        subcategory="execution_chain",
                        severity="critical",
                        weight=95,
                        description=f"Decodes/decompresses data and immediately executes it",
                        user_message=f"🔴 OBFUSCATION CHAIN! {outer}({inner_name}(...)) — decodes hidden code and runs it!",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        line_content=self._get_line_content(node.lineno),
                        matched_pattern=f"{outer}({inner_name}(...))",
                        mitre_attack="T1027",
                        confidence=0.95,
                        context_multiplier=1.5,
                    ))

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""


class ASTAnalyzer:
    """Deep Python AST analysis for detecting malicious code patterns."""

    def scan_file(self, file_path: str, content: str,
                  lines: List[str]) -> List[Finding]:
        """Perform AST analysis on a Python file.

        Args:
            file_path: Path to the Python file.
            content: Full file content.
            lines: List of lines.

        Returns:
            List of Finding objects from AST analysis.
        """
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            # File has syntax errors — can't parse AST
            return []
        except Exception:
            return []

        visitor = MaliciousNodeVisitor(file_path, lines)
        visitor.visit(tree)

        return visitor.findings
