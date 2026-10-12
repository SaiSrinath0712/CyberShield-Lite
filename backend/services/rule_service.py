import re
import math
import mimetypes
from typing import Dict, Any, List

# Initialize standard system MIME types
mimetypes.init()

# --- COMPREHENSIVE FILE EXTENSION THREAT INTELLIGENCE REGISTRY ---

# 1. Critical Executable Binaries & Installers (Direct Machine Code Execution)
CRITICAL_EXECUTABLES = {
    # Windows Binaries
    ".exe": ("Windows Portable Executable binary - direct machine code execution.", "MITRE ATT&CK T1204.002"),
    ".scr": ("Windows Screensaver binary - executes as a standard PE binary, commonly weaponized in phishing.", "MITRE ATT&CK T1204.002"),
    ".dll": ("Dynamic Link Library - executes via rundll32 or performs DLL side-loading/injection.", "MITRE ATT&CK T1574.002"),
    ".com": ("MS-DOS Command executable - runs arbitrary commands directly in legacy subsystem.", "MITRE ATT&CK T1204.002"),
    ".pif": ("Program Information File - legacy shortcut capable of executing arbitrary programs.", "MITRE ATT&CK T1204.002"),
    ".application": ("ClickOnce deployment manifest - can download and execute remote payloads.", "MITRE ATT&CK T1204.002"),
    ".gadget": ("Windows Sidebar Gadget - executes script and binary payloads in background.", "MITRE ATT&CK T1204.002"),
    ".msi": ("Windows Installer package - runs with elevated installer privileges and executes embedded binaries.", "MITRE ATT&CK T1218.007"),
    ".msp": ("Windows Installer patch - applies updates with elevated installer privileges.", "MITRE ATT&CK T1218.007"),
    ".mst": ("Windows Installer transform - can modify MSI execution parameters maliciously.", "MITRE ATT&CK T1218.007"),
    ".cpl": ("Control Panel Item - executes code directly inside Windows shell process via rundll32.", "MITRE ATT&CK T1218.002"),
    ".msc": ("Microsoft Management Console snap-in - can execute unauthorized administrative MMC tasks.", "MITRE ATT&CK T1218"),
    ".sys": ("Windows Kernel Driver - ring-0 driver file, severe threat of kernel-level rootkits.", "MITRE ATT&CK T1068"),
    ".drv": ("Windows Driver file - executes low-level system driver operations.", "MITRE ATT&CK T1068"),
    ".ocx": ("OLE Control Extension - ActiveX binary module capable of arbitrary code execution.", "MITRE ATT&CK T1218"),
    ".reg": ("Windows Registry file - imports registry modifications to establish persistence or disable security.", "MITRE ATT&CK T1112"),

    # Unix / Linux / macOS Executables
    ".elf": ("Linux/Unix ELF binary - native executable machine code.", "MITRE ATT&CK T1204.002"),
    ".so": ("Shared Object Library - dynamic library injection hazard on Linux systems.", "MITRE ATT&CK T1574.001"),
    ".dylib": ("macOS Dynamic Library - dynamic library injection vector on Darwin systems.", "MITRE ATT&CK T1574.001"),
    ".app": ("macOS Application bundle - executes Apple Mach-O binaries.", "MITRE ATT&CK T1204.002"),
    ".dmg": ("Apple Disk Image - commonly used to mount and distribute untrusted macOS binaries.", "MITRE ATT&CK T1553.005"),
    ".pkg": ("macOS / Unix Installer package - executes installation pre/post-install shell scripts.", "MITRE ATT&CK T1204.002"),
    ".deb": ("Debian package - executes root pre/post installation scripts.", "MITRE ATT&CK T1059.004"),
    ".rpm": ("RedHat/RPM package - executes package installation scripts with root privileges.", "MITRE ATT&CK T1059.004"),
    ".apk": ("Android Package Kit - mobile application package capable of installing unauthorized malware.", "MITRE ATT&CK Mobile T1444"),
    ".bin": ("Raw executable binary image / firmware vector.", "MITRE ATT&CK T1204.002"),
    ".run": ("Linux self-extracting executable installer script.", "MITRE ATT&CK T1059.004"),
}

# 2. Dangerous Script Engines & Web Shells
HIGH_RISK_SCRIPTS = {
    # Windows Command & Scripting
    ".bat": ("Windows Batch file - executes arbitrary command-line and PowerShell commands.", "MITRE ATT&CK T1059.003"),
    ".cmd": ("Windows Command script - executes batch console commands under cmd.exe.", "MITRE ATT&CK T1059.003"),
    ".ps1": ("PowerShell Script - executes administrative cmdlets, bypasses execution policy.", "MITRE ATT&CK T1059.001"),
    ".psm1": ("PowerShell Module file - loads custom scripts and cmdlet overrides.", "MITRE ATT&CK T1059.001"),
    ".psd1": ("PowerShell Data file - module manifest with script execution triggers.", "MITRE ATT&CK T1059.001"),
    ".vbs": ("VBScript script - frequently leveraged in malicious email attachments and droppers.", "MITRE ATT&CK T1059.005"),
    ".vbe": ("Encoded VBScript script - obfuscated VBS file designed to evade heuristic detection.", "MITRE ATT&CK T1027"),
    ".js": ("JavaScript script file - executes locally via Windows Script Host (WScript/CScript).", "MITRE ATT&CK T1059.007"),
    ".jse": ("Encoded JScript script - obfuscated JavaScript file used by loaders.", "MITRE ATT&CK T1027"),
    ".wsf": ("Windows Script File - XML-based script container capable of mixing VBS and JScript.", "MITRE ATT&CK T1059.005"),
    ".wsh": ("Windows Script Host settings file - initiates arbitrary script engines.", "MITRE ATT&CK T1059.005"),
    ".hta": ("HTML Application - runs MSHTA engine outside browser sandbox with full system rights.", "MITRE ATT&CK T1218.005"),
    ".inf": ("Setup Information file - executes setup directives via advpack / infDefaultInstall.", "MITRE ATT&CK T1218"),

    # Shell Scripts
    ".sh": ("Unix/Linux Shell script - executes POSIX terminal commands.", "MITRE ATT&CK T1059.004"),
    ".bash": ("Bash Shell script - executes Linux shell commands and curl/wget downloads.", "MITRE ATT&CK T1059.004"),
    ".zsh": ("Z Shell script - executes shell commands under macOS / Linux.", "MITRE ATT&CK T1059.004"),
    ".csh": ("C Shell script - Unix command scripting vector.", "MITRE ATT&CK T1059.004"),
    ".ksh": ("Korn Shell script - Unix administrative scripting file.", "MITRE ATT&CK T1059.004"),

    # Web Shells & Dynamic Interpreters
    ".php": ("PHP Server Script - primary web shell vector allowing Remote Code Execution (RCE).", "MITRE ATT&CK T1505.003"),
    ".phtml": ("PHP Embedded HTML - alternate extension used to bypass .php file upload filters.", "MITRE ATT&CK T1505.003"),
    ".php3": ("Legacy PHP file - alternate web shell extension.", "MITRE ATT&CK T1505.003"),
    ".php4": ("Legacy PHP file - alternate web shell extension.", "MITRE ATT&CK T1505.003"),
    ".php5": ("PHP 5 Script - web shell bypass extension.", "MITRE ATT&CK T1505.003"),
    ".phps": ("PHP Source file - web application attack vector.", "MITRE ATT&CK T1505.003"),
    ".asp": ("Active Server Pages - classic IIS web shell vector for server command execution.", "MITRE ATT&CK T1505.003"),
    ".aspx": ("ASP.NET Server Page - modern IIS web shell vector executing .NET assemblies.", "MITRE ATT&CK T1505.003"),
    ".jsp": ("JavaServer Pages - Java web application shell executing JVM system commands.", "MITRE ATT&CK T1505.003"),
    ".jspx": ("JSP XML Document - XML-based Java web shell bypass vector.", "MITRE ATT&CK T1505.003"),
    ".war": ("Web Application Archive - deploys full malicious servlet packages to Java servers.", "MITRE ATT&CK T1505.003"),
    ".cgi": ("Common Gateway Interface script - executes server-side commands on web hosts.", "MITRE ATT&CK T1059"),
    ".pl": ("Perl Script - scripting interpreter often used in Unix backdoors.", "MITRE ATT&CK T1059"),
    ".py": ("Python Script - executes arbitrary Python code and networking sockets.", "MITRE ATT&CK T1059.006"),
    ".pyw": ("Windowless Python Script - executes Python scripts invisibly in background.", "MITRE ATT&CK T1059.006"),
    ".rb": ("Ruby Script - executes Ruby command sequences.", "MITRE ATT&CK T1059"),
}

# 3. Macro-Enabled Weaponized Documents (Maldocs)
MACRO_DOCUMENTS = {
    ".docm": ("Word Macro-Enabled Document - executes embedded VBA malware upon opening (Emotet/Qakbot vector).", "MITRE ATT&CK T1204.002"),
    ".dotm": ("Word Macro-Enabled Template - auto-executes VBA macros on template load.", "MITRE ATT&CK T1204.002"),
    ".xlsm": ("Excel Macro-Enabled Workbook - executes VBA spreadsheets macros to download payloads.", "MITRE ATT&CK T1204.002"),
    ".xltm": ("Excel Macro-Enabled Template - launches weaponized Excel macros.", "MITRE ATT&CK T1204.002"),
    ".xlam": ("Excel Macro-Enabled Add-In - persistent Excel macro execution vector.", "MITRE ATT&CK T1204.002"),
    ".xla": ("Legacy Excel Add-in with embedded macro capabilities.", "MITRE ATT&CK T1204.002"),
    ".pptm": ("PowerPoint Macro-Enabled Presentation - triggers VBA macros during slide show.", "MITRE ATT&CK T1204.002"),
    ".potm": ("PowerPoint Macro-Enabled Template - macro execution vector.", "MITRE ATT&CK T1204.002"),
    ".ppam": ("PowerPoint Add-in - persistent presentation macro vector.", "MITRE ATT&CK T1204.002"),
    ".ppsm": ("PowerPoint Macro-Enabled Slide Show - auto-executes presentation macros immediately.", "MITRE ATT&CK T1204.002"),
    ".sldm": ("PowerPoint Macro-Enabled Slide - macro slide vector.", "MITRE ATT&CK T1204.002"),
    ".docb": ("Word Binary Document - binary structure obfuscating embedded content.", "MITRE ATT&CK T1204.002"),
    ".iqy": ("Internet Query file - Excel dynamic data exchange (DDE) vector used in phishing.", "MITRE ATT&CK T1204.002"),
    ".slk": ("SYLK Spreadsheet - Excel formula injection and macro execution bypass.", "MITRE ATT&CK T1204.002"),
}

# 4. Shortcuts, Persistence Vectors & Container Droppers
SHORTCUTS_AND_CONTAINERS = {
    ".lnk": ("Windows Shortcut file - weaponized LNK file executes hidden PowerShell/cmd payloads.", "High", "MITRE ATT&CK T1204.001"),
    ".url": ("Internet Shortcut file - can invoke external protocol handlers and SMB share attacks.", "High", "MITRE ATT&CK T1204.001"),
    ".scf": ("Windows Shell Command File - triggers automatic NTLM hash theft via SMB connections.", "High", "MITRE ATT&CK T1187"),
    ".settingcontent-ms": ("Windows SettingContent XML - executes commands directly via DeepLink triggers.", "Critical", "MITRE ATT&CK T1218"),
    ".iso": ("Optical Disc Image - frequently abused to bypass Windows Mark-of-the-Web (MOTW).", "High", "MITRE ATT&CK T1553.005"),
    ".img": ("Raw Disk Image - container format used to smuggle malicious binaries past email filters.", "High", "MITRE ATT&CK T1553.005"),
    ".vhd": ("Virtual Hard Disk - virtual disk container used in MOTW bypass malware campaigns.", "High", "MITRE ATT&CK T1553.005"),
    ".vhdx": ("Hyper-V Virtual Hard Disk - disk container vector used to deliver droppers.", "High", "MITRE ATT&CK T1553.005"),
    ".chm": ("Compiled HTML Help file - executes embedded ActiveX commands via hh.exe.", "High", "MITRE ATT&CK T1218.001"),
    ".jar": ("Java Archive executable - runs Java bytecode with client system privileges.", "Medium", "MITRE ATT&CK T1204.002"),
    ".cab": ("Windows Cabinet Archive - can extract and execute embedded setup routines.", "Medium", "MITRE ATT&CK T1204"),
}

# 5. Suspicious / Evasive Archives
SUSPICIOUS_ARCHIVES = {
    ".ace": ("WinAce Archive file - known for historic WinRAR path traversal vulnerabilities (CVE-2018-20250).", "Medium"),
    ".arj": ("ARJ Compressed Archive - obsolete archive format commonly seen in evasion spam.", "Medium"),
    ".lzh": ("LHA/LZH Compressed Archive - legacy format used in AV evasion.", "Medium"),
    ".uue": ("UUEncoded file - text-encoded binary format used to bypass gateway email scanners.", "Medium"),
}

# 6. Standard Safe Formats (Registered IANA Documents, Media, Data)
SAFE_EXTENSIONS = {
    # Documents
    ".pdf": "Adobe Acrobat Document",
    ".docx": "Microsoft Word Document (Macro-Free)",
    ".doc": "Microsoft Word Legacy Document",
    ".xlsx": "Microsoft Excel Workbook (Macro-Free)",
    ".xls": "Microsoft Excel Legacy Workbook",
    ".pptx": "Microsoft PowerPoint Presentation (Macro-Free)",
    ".ppt": "Microsoft PowerPoint Legacy Presentation",
    ".odt": "OpenDocument Text Document",
    ".ods": "OpenDocument Spreadsheet",
    ".odp": "OpenDocument Presentation",
    ".txt": "Plain Text Document",
    ".rtf": "Rich Text Format Document",
    ".csv": "Comma-Separated Values Data",
    ".tsv": "Tab-Separated Values Data",
    ".md": "Markdown Document",
    ".epub": "Electronic Publication E-Book",

    # Images
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image",
    ".png": "Portable Network Graphics Image",
    ".gif": "Graphics Interchange Format Image",
    ".bmp": "Bitmap Image",
    ".webp": "WebP Image",
    ".svg": "Scalable Vector Graphics Image",
    ".ico": "Icon Resource Image",
    ".tif": "Tagged Image File Format",
    ".tiff": "Tagged Image File Format",
    ".psd": "Adobe Photoshop Document",
    ".ai": "Adobe Illustrator File",
    ".heic": "High Efficiency Image Container",
    ".raw": "Raw Camera Sensor Image",
    ".avif": "AV1 Image File Format",

    # Audio
    ".mp3": "MPEG-3 Audio",
    ".wav": "Waveform Audio File Format",
    ".ogg": "Ogg Vorbis Audio",
    ".flac": "Free Lossless Audio Codec",
    ".aac": "Advanced Audio Coding",
    ".m4a": "Apple MPEG-4 Audio",
    ".wma": "Windows Media Audio",

    # Video
    ".mp4": "MPEG-4 Video",
    ".mkv": "Matroska Video Container",
    ".avi": "Audio Video Interleave Container",
    ".mov": "Apple QuickTime Movie",
    ".wmv": "Windows Media Video",
    ".webm": "WebM Video Container",
    ".flv": "Flash Video Container",
    ".m4v": "Apple Video File",

    # Standard Archives
    ".zip": "Standard ZIP Archive",
    ".tar": "Tape Archive File",
    ".gz": "Gzip Compressed File",
    ".bz2": "Bzip2 Compressed File",
    ".xz": "XZ Compressed File",
    ".7z": "7-Zip Compressed Archive",
    ".rar": "WinRAR Compressed Archive",

    # Web & Configuration Data
    ".json": "JavaScript Object Notation Data",
    ".xml": "Extensible Markup Language File",
    ".yaml": "YAML Data Configuration",
    ".yml": "YAML Data Configuration",
    ".html": "HyperText Markup Language Page",
    ".htm": "HyperText Markup Language Page",
    ".css": "Cascading Style Sheet",
    ".ini": "Configuration INI File",
    ".log": "Plain Text Log File",

    # Fonts
    ".ttf": "TrueType Font",
    ".otf": "OpenType Font",
    ".woff": "Web Open Font Format",
    ".woff2": "Web Open Font Format 2.0",
    ".eot": "Embedded OpenType Font",
}

# Backward compatibility alias
UNSAFE_EXTENSIONS = {k: (v[0], "Critical" if "Critical" in v[1] else "High") for k, v in CRITICAL_EXECUTABLES.items()}
UNSAFE_EXTENSIONS.update({k: (v[0], "High") for k, v in HIGH_RISK_SCRIPTS.items()})

def calculate_filename_entropy(text: str) -> float:
    """Calculates Shannon entropy on base filename to detect automated random generation."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def scan_file_extension(filename: str, ext: str) -> Dict[str, Any]:
    """
    Performs real-time, multi-layered cybersecurity analysis on file extension and filename.
    Detects executable binaries, scripting vectors, maldoc macros, container smuggling,
    Right-to-Left Override (RTLO) spoofing, double extension masquerading, and extension mismatches.
    """
    filename_raw = str(filename or "").strip()
    ext_raw = str(ext or "").strip().lower()

    # 1. Parse extensions from filename
    filename_clean = filename_raw
    filename_lower = filename_clean.lower()
    name_parts = [p for p in filename_lower.split(".") if p]
    file_ext_tokens = [f".{p}" for p in name_parts[1:]] if len(name_parts) > 1 else []

    # 2. Parse extensions from ext input field
    ext_tokens = [f".{part}" for part in ext_raw.replace(" ", "").split(".") if part]

    # 3. Determine actual extension chain and terminating extension
    dangerous_set = set(CRITICAL_EXECUTABLES.keys()) | set(HIGH_RISK_SCRIPTS.keys()) | set(MACRO_DOCUMENTS.keys()) | set(SHORTCUTS_AND_CONTAINERS.keys())
    has_mismatch = False

    if len(ext_tokens) >= 2:
        # User entered multi-extension in ext box (e.g. ext=".pdf.exe" with filename="invoice")
        all_ext_tokens = ext_tokens
        canonical_filename = f"{filename_raw.rstrip('.')}{''.join(ext_tokens)}" if filename_raw else f"sample{''.join(ext_tokens)}"
    elif len(file_ext_tokens) >= 2:
        # Filename itself contains multi-extension (e.g. filename="invoice.pdf.exe")
        all_ext_tokens = file_ext_tokens
        canonical_filename = filename_raw
    elif file_ext_tokens and ext_tokens and file_ext_tokens[-1] != ext_tokens[-1]:
        # Both filename and ext have 1 extension, but they conflict! (e.g. filename="document.exe", ext="pdf")
        has_mismatch = True
        canonical_filename = filename_raw
        if file_ext_tokens[-1] in dangerous_set:
            all_ext_tokens = file_ext_tokens
        elif ext_tokens[-1] in dangerous_set:
            all_ext_tokens = ext_tokens
        else:
            all_ext_tokens = file_ext_tokens
    elif file_ext_tokens:
        all_ext_tokens = file_ext_tokens
        canonical_filename = filename_raw
    elif ext_tokens:
        all_ext_tokens = ext_tokens
        canonical_filename = f"{filename_raw.rstrip('.')}{''.join(ext_tokens)}" if filename_raw else f"sample{''.join(ext_tokens)}"
    else:
        all_ext_tokens = []
        canonical_filename = filename_raw

    # The terminating extension is what the operating system will execute
    final_ext = all_ext_tokens[-1] if all_ext_tokens else ""
    target_ext = final_ext

    reasons: List[str] = []
    suggestions: List[str] = []
    verdict = "Safe"
    risk_level = "Low"
    is_unsafe = False
    confidence = 98.0
    category = "Unknown"

    # --- CHECK 1: Unicode Right-to-Left Override (RTLO) Evasion ---
    has_rtlo = bool(re.search(r"[\u202A-\u202E\u2066-\u2069]", filename_clean))
    if has_rtlo:
        is_unsafe = True
        verdict = "Dangerous"
        risk_level = "Critical"
        confidence = 99.9
        reasons.append("Right-to-Left Override (RTLO / U+202E) spoofing detected! Attackers use bidirectional control characters to reverse file extension presentation in user interfaces [MITRE ATT&CK T1036.002].")

    # --- CHECK 2: Null Byte & URL Encoding Injection ---
    has_null_byte = bool(re.search(r"(%00|\x00|%2e|%2f)", filename_clean, re.I))
    if has_null_byte:
        is_unsafe = True
        verdict = "Dangerous"
        risk_level = "Critical"
        confidence = 99.5
        reasons.append("Null byte / hex encoding injection detected (%00/\\x00). Attackers use null-byte termination to bypass filename extension filters [CWE-626].")

    # --- CHECK 3: Whitespace Padding / Dot Smuggling ---
    has_padding = bool(re.search(r"\.[a-zA-Z0-9]+\s+\.[a-zA-Z0-9]+", filename_clean)) or bool(re.search(r"\.{2,}", filename_clean))
    if has_padding:
        is_unsafe = True
        if verdict != "Dangerous":
            verdict = "Dangerous"
            risk_level = "High"
        confidence = max(confidence, 96.0)
        reasons.append("Whitespace padding or multiple dot obfuscation detected. Used to push executable extension beyond visible GUI file dialog boundaries.")

    # --- CHECK 4: Double / Multiple Extension Masquerading ---
    # Triggered whenever 2 or more extension segments exist in filename or extension input
    has_double_ext = False
    has_multiple_ext = False

    if len(all_ext_tokens) >= 2:
        preceding_ext = all_ext_tokens[-2]
        ext_chain_str = "".join(all_ext_tokens)

        # If terminating with an executable, script, macro, shortcut or container
        if final_ext in dangerous_set:
            has_double_ext = True
            is_unsafe = True
            verdict = "Dangerous"
            risk_level = "Critical"
            confidence = 99.8
            reasons.append(f"Double extension masquerading detected: '{ext_chain_str}' [MITRE ATT&CK T1036.007]. Disguises malicious '{final_ext}' payload behind decoy '{preceding_ext}' file extension.")
        else:
            has_multiple_ext = True
            is_unsafe = True
            if verdict != "Dangerous":
                verdict = "Suspicious"
                risk_level = "Medium"
            confidence = max(confidence, 85.0)
            reasons.append(f"Multiple file extensions detected: '{ext_chain_str}'. Files containing two or more extensions are anomalous and frequently used in deceptive masquerading campaigns.")

    # --- CHECK 5: Extension Mismatch Analysis ---
    if has_mismatch and file_ext_tokens and ext_tokens:
        reasons.append(f"Extension Mismatch: Declared extension '{ext_tokens[-1]}' conflicts with actual filename extension '{file_ext_tokens[-1]}'. Indicates deceptive header masquerading [MITRE ATT&CK T1036].")
        if file_ext_tokens[-1] in dangerous_set or ext_tokens[-1] in dangerous_set:
            is_unsafe = True
            verdict = "Dangerous"
            if risk_level != "Critical":
                risk_level = "High"
            confidence = max(confidence, 96.0)
            target_ext = file_ext_tokens[-1] if file_ext_tokens[-1] in dangerous_set else ext_tokens[-1]

    # --- CHECK 6: Categorized Threat Rules Evaluation ---
    if target_ext in CRITICAL_EXECUTABLES:
        desc, mitre = CRITICAL_EXECUTABLES[target_ext]
        is_unsafe = True
        verdict = "Dangerous"
        risk_level = "Critical"
        confidence = max(confidence, 99.5)
        category = "Executable Binary"
        reasons.append(f"Direct Executable Binary: '{target_ext}'. {desc} [{mitre}].")
    elif target_ext in HIGH_RISK_SCRIPTS:
        desc, mitre = HIGH_RISK_SCRIPTS[target_ext]
        is_unsafe = True
        verdict = "Dangerous"
        risk_level = "Critical" if target_ext in [".ps1", ".vbs", ".hta", ".php", ".aspx"] else "High"
        confidence = max(confidence, 98.0)
        category = "Script Engine / Web Shell"
        reasons.append(f"Dangerous Script/Shell Engine: '{target_ext}'. {desc} [{mitre}].")
    elif target_ext in MACRO_DOCUMENTS:
        desc, mitre = MACRO_DOCUMENTS[target_ext]
        is_unsafe = True
        verdict = "Dangerous"
        risk_level = "High"
        confidence = max(confidence, 97.0)
        category = "Macro-Enabled Document"
        reasons.append(f"Weaponized Macro Document: '{target_ext}'. {desc} [{mitre}].")
    elif target_ext in SHORTCUTS_AND_CONTAINERS:
        desc, sev, mitre = SHORTCUTS_AND_CONTAINERS[target_ext]
        is_unsafe = True
        verdict = "Dangerous" if sev in ["Critical", "High"] else "Suspicious"
        risk_level = sev
        confidence = max(confidence, 94.0)
        category = "Container / Shortcut Vector"
        reasons.append(f"Shortcut / Container Evasion: '{target_ext}'. {desc} [{mitre}].")
    elif target_ext in SUSPICIOUS_ARCHIVES:
        desc, sev = SUSPICIOUS_ARCHIVES[target_ext]
        is_unsafe = True
        if verdict != "Dangerous":
            verdict = "Suspicious"
            risk_level = sev
        confidence = max(confidence, 86.0)
        category = "Suspicious Archive"
        reasons.append(f"Suspicious Archive Format: '{target_ext}'. {desc}")
    elif target_ext in SAFE_EXTENSIONS:
        desc = SAFE_EXTENSIONS[target_ext]
        category = "Standard Safe Format"
        if not is_unsafe:
            verdict = "Safe"
            risk_level = "Low"
            confidence = 99.0
            reasons.append(f"Standard Verified Format: '{target_ext}' ({desc}). Registered in IANA media registry for normal document and media operations.")
    else:
        # Unknown or unassigned extension
        category = "Unrecognized Extension"
        if not is_unsafe:
            verdict = "Suspicious"
            risk_level = "Medium"
            confidence = 78.0
            is_unsafe = True
            reasons.append(f"Unrecognized Extension: '{target_ext}' is not registered in standard IANA safe file categories. Could be custom binary payload or obfuscated data vector.")

    # --- CHECK 7: Base Filename Entropy & Randomness Diagnostics ---
    base_name = name_parts[0] if name_parts else filename_clean
    entropy = calculate_filename_entropy(base_name)
    if entropy > 4.2 and len(base_name) >= 10:
        reasons.append(f"High Filename Entropy ({entropy:.2f}): Randomly generated string characteristic of automated DGA malware droppers or ransomware encryptions.")
        if verdict == "Safe":
            verdict = "Suspicious"
            risk_level = "Medium"
            is_unsafe = True
        confidence = min(confidence + 3.0, 99.9)

    # --- CHECK 8: MIME Type Resolution ---
    guessed_mime, _ = mimetypes.guess_type(f"file{target_ext}")
    if not guessed_mime:
        if target_ext in CRITICAL_EXECUTABLES:
            guessed_mime = "application/x-msdownload" if target_ext in [".exe", ".scr", ".dll"] else "application/octet-stream"
        elif target_ext in HIGH_RISK_SCRIPTS:
            guessed_mime = "application/x-sh" if target_ext in [".sh", ".bash"] else "text/x-script"
        elif target_ext in MACRO_DOCUMENTS:
            guessed_mime = "application/vnd.ms-office.activeX+xml"
        else:
            guessed_mime = "application/octet-stream"

    # --- REMEDIATION TIPS ---
    if verdict == "Dangerous":
        suggestions = [
            "Do NOT open, double-click, or execute this file under standard operating system privileges.",
            "Inspect the origin email, download URL, and digital code-signing certificate.",
            "Submit file hash to VirusTotal or sandbox environment (e.g. Any.Run, Cuckoo) for dynamic behavioral analysis.",
            "Verify endpoint EDR / Antivirus signatures are updated to latest heuristic definitions."
        ]
    elif verdict == "Suspicious":
        suggestions = [
            "Verify file source with sender through an out-of-band communication channel.",
            "Confirm expected file format matches application requirements before opening.",
            "Scan file with local security software prior to extraction or execution."
        ]
    else:
        suggestions = [
            "File format conforms to registered standard specifications.",
            "Maintain baseline security hygiene and ensure macro execution remains disabled by default.",
            "Keep anti-virus file monitoring active."
        ]

    threat_type = "Malicious File Extension" if is_unsafe else "Safe File"
    if has_double_ext:
        threat_type = "Double Extension Spoofing"
    elif has_rtlo:
        threat_type = "RTLO Masquerading Attack"

    return {
        "verdict": verdict,
        "is_unsafe": is_unsafe,
        "explanation": {
            "verdict": verdict,
            "threat_type": threat_type,
            "confidence": round(confidence, 2),
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {
                "extension": target_ext,
                "category": category,
                "mime_type": guessed_mime,
                "double_extension": has_double_ext,
                "extension_mismatch": has_mismatch,
                "rtlo_spoofing": has_rtlo,
                "filename_entropy": round(entropy, 2),
                "is_dangerous": is_unsafe
            }
        }
    }


# --- SQL INJECTION DETECTOR ---
SQL_KEYWORDS = [
    (r"(?i)\bUNION\b.*\bSELECT\b", "UNION SELECT query bypass"),
    (r"(?i)\bSELECT\b.*\bFROM\b", "Unauthorized SELECT database query"),
    (r"(?i)\bDROP\b\s+\bTABLE\b", "Database table DROP command"),
    (r"(?i)\bINSERT\b\s+\bINTO\b", "Database INSERT command"),
    (r"(?i)\bDELETE\b\s+\bFROM\b", "Database DELETE command"),
    (r"(?i)\bEXEC(\b|\s+|\()", "Database shell execution block (EXEC)"),
    (r"(?i)\bxp_cmdshell\b", "SQL Server shell injection (xp_cmdshell)"),
    (r"(?i)\bOR\b\s+\d+\s*=\s*\d+", "Tautology pattern bypass (e.g. OR 1=1)"),
    (r"(?i)'\s*OR\s*'\d+'\s*=\s*'\d+", "Tautology quote bypass (e.g. ' OR '1'='1)")
]

def scan_sql_injection(query_text: str) -> Dict[str, Any]:
    triggered = []
    
    for pattern, reason in SQL_KEYWORDS:
        if re.search(pattern, query_text):
            triggered.append(reason)
            
    is_injection = len(triggered) > 0
    verdict = "Dangerous" if is_injection else "Safe"
    risk_level = "Critical" if is_injection else "Low"
    confidence = 95.0 if is_injection else 100.0
    
    reasons = triggered if is_injection else ["No SQL injection patterns matched."]
    suggestions = []
    if is_injection:
        suggestions = [
            "Use parameterized SQL query statements or ORMs.",
            "Sanitize input forms using strict white-list regex filters.",
            "Apply principle of least privilege permissions to database user connection profiles."
        ]
    else:
        suggestions = ["Standard input query validation. Keep input validation frameworks active."]

    return {
        "verdict": verdict,
        "is_injection": is_injection,
        "explanation": {
            "verdict": verdict,
            "threat_type": "SQL Injection Attack" if is_injection else "Safe Input Query",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"matched_rules_count": len(triggered), "rules": triggered}
        }
    }


# --- XSS DETECTOR ---
XSS_PATTERNS = [
    (r"(?i)<script\b[^>]*>", "Script tag block injection (<script>)"),
    (r"(?i)\bon\w+\s*=", "HTML attribute script event handler (e.g. onerror, onload)"),
    (r"(?i)javascript\s*:", "Javascript inline protocol header (javascript:)"),
    (r"(?i)<iframe\b[^>]*>", "IFrame clickjacking wrapper frame (<iframe)"),
    (r"(?i)alert\s*\(", "Execution call to display alerts (alert())"),
    (r"(?i)document\.cookie", "Cookie session hijacking command (document.cookie)")
]

def scan_xss(payload_text: str) -> Dict[str, Any]:
    triggered = []
    
    for pattern, reason in XSS_PATTERNS:
        if re.search(pattern, payload_text):
            triggered.append(reason)
            
    is_xss = len(triggered) > 0
    verdict = "Dangerous" if is_xss else "Safe"
    risk_level = "High" if is_xss else "Low"
    confidence = 96.0 if is_xss else 100.0
    
    reasons = triggered if is_xss else ["No XSS payloads matched."]
    suggestions = []
    if is_xss:
        suggestions = [
            "Perform HTML Entity Encoding on all user inputs before displaying them.",
            "Set strict Content Security Policy (CSP) headers.",
            "Implement HttpOnly and Secure attributes on cookies."
        ]
    else:
        suggestions = ["Standard input script validation. Safe to display."]

    return {
        "verdict": verdict,
        "is_xss": is_xss,
        "explanation": {
            "verdict": verdict,
            "threat_type": "XSS Injection Attack" if is_xss else "Safe Form Input",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"matched_rules_count": len(triggered), "rules": triggered}
        }
    }


# --- LOGIN MONITOR ---
def scan_login_attempts(username: str, ip_address: str, failed_count: int, window: int) -> Dict[str, Any]:
    is_brute_force = False
    verdict = "Safe"
    risk_level = "Low"
    reasons = []
    suggestions = []
    confidence = 100.0

    if failed_count >= 5:
        is_brute_force = True
        verdict = "Dangerous"
        risk_level = "Critical"
        confidence = 98.0
        reasons.append(f"Brute-force attack warning: Account '{username}' triggered {failed_count} failed logins within {window} seconds from IP {ip_address}.")
    elif failed_count >= 3:
        is_brute_force = True
        verdict = "Suspicious"
        risk_level = "Medium"
        confidence = 80.0
        reasons.append(f"Multiple failed logins detected: {failed_count} failures for user '{username}' on host {ip_address}.")
    else:
        reasons.append(f"Normal access rate: {failed_count} login failures on record.")
        
    if is_brute_force:
        suggestions = [
            "Temporarily lock the user account or block requests from this source IP.",
            "Require Multi-Factor Authentication (MFA) challenge validation.",
            "Alert the account owner about unauthorized access attempts."
        ]
    else:
        suggestions = ["Normal logins audit logs. Keep access control systems active."]

    return {
        "verdict": verdict,
        "is_brute_force": is_brute_force,
        "explanation": {
            "verdict": verdict,
            "threat_type": "Brute Force Attack" if is_brute_force else "Normal Login Activity",
            "confidence": confidence,
            "risk_level": risk_level,
            "reasons": reasons,
            "suggestions": suggestions,
            "features_triggered": {"failed_attempts": failed_count, "ip": ip_address}
        }
    }
