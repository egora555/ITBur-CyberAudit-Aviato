import os
import re

# Отдельный модуль, был заимствован
# Сделан: -, ссылка на модуль: -

def scan_file_for_secrets(file_path, patterns, context_lines=0):
    """Scans file for secrets with context support"""
    secrets_found = []

    if not os.path.exists(file_path):
        print(f"Warning: {file_path} не существует, пропускаем")
        return []

    if os.path.getsize(file_path) > 10 * 1024 * 1024:
        print(f"Warning: {file_path} слишком большой, пропускаем")
        return []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            if pattern.search(line):
                if is_false_positive(line, file_path):
                    continue

                secrets_found.append({
                    'file': file_path,
                    'line': i,
                    'content': line.strip(),
                    'pattern': pattern.pattern
                })
    return secrets_found


def is_false_positive(line, file_path):
    """Checks on false triggers."""

    code_indicators = [
        'def ', 'class ', 'import ', 'from ', 'return ',
        'if ', 'else:', 'for ', 'in ', 'not in',
        'print(', 'f"', '.append', '.extend',
    ]

    for indicator in code_indicators:
        if indicator in line:
            return True

    if 'Рекомендация:' in line or 'рекомендуется' in line.lower():
        return True

    variable_patterns = ['port_key', 'key =', 'secret[']
    for pattern in variable_patterns:
        if pattern in line:
            return True

    if file_path.endswith('.pyc'):
        return True

    return False

def scan_directory_for_secrets(directory_path, patterns, extensions):
    secrets_found = []
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]

    for root, _, files in os.walk(directory_path):
        if any(skip in root for skip in ['.git', '__pycache__', 'node_modules']):
            continue

        for file in files:
            if extensions == ['all'] or any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                secrets_found.extend(
                    scan_file_for_secrets(file_path, compiled_patterns)
                )

    return secrets_found