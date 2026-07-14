"""Hardware and OS permission detection for RepoSentinel.

Detects when code attempts to access sensitive hardware (camera, mic)
or OS-level permissions (clipboard, root access).
"""

import re
from typing import List, Tuple

from reposentinel.database.severity import Finding


class PermissionAnalyzer:
    """Detects permission-sensitive patterns in code."""

    # Define permission categories with their detection patterns
    PERMISSION_CHECKS = {
        "camera": {
            "emoji": "📷",
            "label": "Camera/Webcam Access",
            "patterns": [
                r"VideoCapture\s*\(\s*0\s*\)",
                r"cv2\.VideoCapture",
                r"getUserMedia\s*\(.*video\s*:\s*true",
                r"AVCaptureSession",
                r"android\.hardware\.Camera",
                r"android\.permission\.CAMERA"
            ],
        },
        "microphone": {
            "emoji": "🎤",
            "label": "Microphone/Audio Access",
            "patterns": [
                r"import\s+pyaudio",
                r"import\s+sounddevice",
                r"sounddevice\.rec",
                r"getUserMedia\s*\(.*audio\s*:\s*true",
                r"AVAudioRecorder",
                r"android\.permission\.RECORD_AUDIO"
            ],
        },
        "screen_capture": {
            "emoji": "🖥️",
            "label": "Screen Capture/Recording",
            "patterns": [
                r"import\s+mss",
                r"ImageGrab\.grab",
                r"pyautogui\.screenshot",
                r"getDisplayMedia",
                r"MediaProjection"
            ],
        },
        "keylogging": {
            "emoji": "⌨️",
            "label": "Keyboard/Keystroke Capture",
            "patterns": [
                r"pynput\.keyboard.*Listener",
                r"import\s+keyboard",
                r"SetWindowsHookEx",
                r"WH_KEYBOARD_LL",
                r"GetAsyncKeyState",
                r"addEventListener\s*\(['\"]key(down|press|up)['\"]"
            ],
        },
        "clipboard": {
            "emoji": "📋",
            "label": "Clipboard Access",
            "patterns": [
                r"pyperclip\.paste",
                r"win32clipboard",
                r"GetClipboardData",
                r"navigator\.clipboard\.readText",
                r"pbpaste",
                r"xclip\s+-o"
            ],
        },
        "location": {
            "emoji": "📍",
            "label": "Location/GPS Access",
            "patterns": [
                r"geolocation\.getCurrentPosition",
                r"navigator\.geolocation",
                r"CLLocationManager",
                r"android\.permission\.ACCESS_FINE_LOCATION"
            ],
        },
        "bluetooth": {
            "emoji": "📶",
            "label": "Bluetooth Access",
            "patterns": [
                r"import\s+bluetooth",
                r"navigator\.bluetooth",
                r"android\.permission\.BLUETOOTH"
            ],
        },
        "admin_privilege": {
            "emoji": "🔑",
            "label": "Administrator/Root Privilege",
            "patterns": [
                r"os\.getuid\s*\(\s*\)\s*==\s*0",
                r"RunAs.*administrator",
                r"ShellExecuteW.*runas",
                r"IsUserAnAdmin",
                r"RequireAdministrator"
            ],
        },
        "network_listen": {
            "emoji": "🌐",
            "label": "Network Server/Listener",
            "patterns": [
                r"socket\.bind\s*\(",
                r"listen\s*\(\s*[0-9]+\s*\)",
                r"netcat\s+-l",
                r"nc\s+-l"
            ],
        },
        "file_system": {
            "emoji": "📁",
            "label": "Sensitive File Access",
            "patterns": [
                r"/etc/shadow",
                r"/etc/passwd",
                r"\.ssh/id_rsa",
                r"\.aws/credentials",
                r"\.kube/config"
            ],
        },
        "browser_data": {
            "emoji": "🌍",
            "label": "Browser Data Access",
            "patterns": [
                r"Chrome/User Data/Default/Login Data",
                r"Mozilla/Firefox/Profiles",
                r"AppData.*Chrome.*Cookies",
                r"document\.cookie"
            ],
        },
        "credentials": {
            "emoji": "🔐",
            "label": "Credential/Password Access",
            "patterns": [
                r"import\s+keyring",
                r"Security/Keychain",
                r"mimikatz",
                r"sekurlsa::logonpasswords"
            ],
        },
        "background_service": {
            "emoji": "👻",
            "label": "Background Service/Daemon",
            "patterns": [
                r"python-daemon",
                r"os\.fork\s*\(\s*\)",
                r"/etc/systemd/system/.*\.service",
                r"Library/LaunchAgents"
            ],
        },
    }

    def __init__(self):
        # Compile regex patterns
        self.compiled_checks = {}
        for category, data in self.PERMISSION_CHECKS.items():
            compiled = [re.compile(p, re.IGNORECASE) for p in data["patterns"]]
            self.compiled_checks[category] = {
                "emoji": data["emoji"],
                "label": data["label"],
                "patterns": compiled
            }

    def scan_file(self, file_path: str, content: str, lines: List[str],
                  language: str) -> Tuple[List[Finding], List[str]]:
        """Detect permission-sensitive patterns in code.

        Args:
            file_path: Path to the file.
            content: Full file content.
            lines: List of lines.
            language: Detected programming language.

        Returns:
            Tuple of (findings list, list of detected permission labels).
        """
        findings = []
        detected_permissions = set()

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith(('#', '//', '/*', '*')):
                continue

            for category, data in self.compiled_checks.items():
                for compiled_regex in data["patterns"]:
                    match = compiled_regex.search(line_stripped)
                    if match:
                        detected_permissions.add(f"{data['emoji']} {data['label']}")
                        
                        # We don't need to create Findings for everything here,
                        # as PatternMatcher handles the severe ones.
                        # We just want to extract the permission requested.
                        # But we can create INFO-level findings to record it.
                        findings.append(Finding(
                            rule_id=f"PERM-{category.upper()}",
                            name=f"Permission Requested: {data['label']}",
                            category="permission",
                            subcategory=category,
                            severity="info",
                            weight=10,
                            description=f"Script accesses: {data['label']}",
                            user_message=f"{data['emoji']} Accesses {data['label']}",
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line_stripped[:100],
                            matched_pattern=match.group(0),
                            mitre_attack="",
                        ))
                        break  # One match per category per line is enough

        return findings, sorted(list(detected_permissions))
