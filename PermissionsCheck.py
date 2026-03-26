import os
import stat
import re
from pathlib import Path
from typing import NamedTuple, Generator, Iterator

import SecretsCheck

ROOT = os.path.sep
CURRENT_DIRECTORY = os.getcwd()
USER_DIRECTORY = str(Path.home())
KEY_DIRECTORIES = ['/etc', '/var', '/home']

# Обычные паттерны для секретов
SECRET_PATTERNS = [
    # password/passwd — с границами слова, значение минимум 4 символа
    re.compile(r'\bpassword\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bpasswd\s*[=:]\s*\S{4,}', re.IGNORECASE),

    # secret — только как отдельное слово
    re.compile(r'\bsecret\s*[=:]\s*\S{4,}', re.IGNORECASE),

    # конкретные виды ключей — не просто "key"
    re.compile(r'\bapi[_-]key\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bapi[_-]secret\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bprivate[_-]key\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bsecret[_-]key\s*[=:]\s*\S{4,}', re.IGNORECASE),

    # токены — только с контекстом
    re.compile(r'\baccess[_-]token\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bapi[_-]token\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\bauth[_-]token\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'\brefresh[_-]token\s*[=:]\s*\S{4,}', re.IGNORECASE),

    # AWS ключи — специфичный формат, почти нет ложных срабатываний
    re.compile(r'AKIA[0-9A-Z]{16}'),

    # JWT токены — характерная структура
    re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),

    # .env стиль — KEY="value" где KEY явно секретное
    re.compile(r'\b(?:DB|DATABASE)_(?:PASSWORD|PASS|SECRET)\s*[=:]\s*\S{4,}', re.IGNORECASE),
]

# Пути, которые не проверяются для оптимизации
EXCLUDED_PATHS = ({
    '/proc', '/sys', '/dev', '/run',
    '/snap', '/boot', '/lost+found',
    "/"
})

# Максимальный размер
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

class WarningInfo(NamedTuple):
    """Информация о предупреждении"""
    message: str
    level: str
    code: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.message}"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "level": self.level,
            "message": self.message,
        }

def _should_skip(path: str) -> bool:
    """
    Проверяет, стоит ли пропустить.

    Args:
        path (str): путь

    Returns:
        bool: стоит ли пропустить?
    """
    return any(path == ep or path.startswith(ep + '/') for ep in EXCLUDED_PATHS)


def _iter_walk(root_path: str) -> Iterator[tuple[str, list, list]]:
    """
    Рекурсивно проходится по файлам

    Args:
        root_path (str): корневая директория для проверки

    Yields:
        TODO: записать
    """
    for root, dirs, files in os.walk(root_path, followlinks=False):
        dirs[:] = [
            d for d in dirs
            if not _should_skip(os.path.join(root, d))
        ]
        yield root, dirs, files


def check_file_for_secrets(file_path: str) -> list[WarningInfo]:
    """
    Проверяет содержимое файла на наличие секретов.

    Args:
        file_path: путь к файлу

    Returns:
        list[WarningInfo]: Список предупреждений типа WarningInfo
    """

    try:
        # Проверка на размер файла для оптимизации
        if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
            return []
    except OSError:
        return []

    secrets = SecretsCheck.scan_file_for_secrets(file_path, SECRET_PATTERNS)

    return [
        WarningInfo(
            message=f"Файл имеет секреты! ({s['content']})",
            level="HIGH",
            code="SECRET-FOUND",
        )
        for s in secrets
    ]


def check_permissions(path: str) -> list[WarningInfo]:
    """
    Проверяет файл на права

    Args:
        path (str): путь к файлу

    Returns:
        List[WarningInfo]: предупреждения к файлу
    """
    
    try:
        st = os.stat(path)
        mode = st.st_mode
    except OSError as e:
        return [WarningInfo(
            message=f"Ошибка доступа: {e}",
            level="ERROR",
            code="PERM-ERROR",
        )]

    warnings: list[WarningInfo] = []
    perm_bits = mode & 0o777
    is_dir = stat.S_ISDIR(mode)

    if perm_bits == 0o777:
        warnings.append(WarningInfo(
            message="Полные права для всех (777) - чрезвычайно опасно!",
            level="CRITICAL",
            code="PERM-777",
        ))
    elif perm_bits == 0o666:
        warnings.append(WarningInfo(
            message="Полный доступ на чтение/запись для всех (666)",
            level="CRITICAL",
            code="PERM-666",
        ))
    elif mode & stat.S_IWOTH:
        warnings.append(WarningInfo(
            message="Файл доступен на запись всем пользователям",
            level="HIGH" if not is_dir else "MEDIUM",
            code="PERM-WORLD-WRITE",
        ))

    if mode & stat.S_ISUID:
        warnings.append(WarningInfo(
            message="Установлен SUID бит (файл выполняется с правами владельца)",
            level="HIGH",
            code="PERM-SUID",
        ))

    if mode & stat.S_ISGID:
        warnings.append(WarningInfo(
            message="Установлен SGID бит (файл выполняется с правами группы)",
            level="MEDIUM",
            code="PERM-SGID",
        ))

    if is_dir and (mode & stat.S_ISVTX):
        if path not in ('/tmp', '/var/tmp') and not path.startswith('/var/tmp/'):
            warnings.append(WarningInfo(
                message="Sticky bit установлен на нестандартной директории",
                level="LOW",
                code="PERM-STICKY",
            ))

    print("file", path, "results: ", warnings)

    return warnings


def check_directory_files(
    path: str,
    check_secrets: bool = True,
) -> Generator[tuple[str, list[WarningInfo]], None, None]:
    """
    Обходит директорию и отдаёт (путь, предупреждения) по одному

    Args:
        path:          путь к директории
        check_secrets: проверять содержимое файлов на секреты

    Yields:
        Кортеж (путь, список предупреждений)
    """
    for root, _dirs, files in _iter_walk(path):
        dir_warnings = check_permissions(root)
        if dir_warnings:
            yield root, dir_warnings

        for file_name in files:
            file_path = os.path.join(root, file_name)

            if os.path.islink(file_path):
                continue

            file_warnings = check_permissions(file_path)

            if check_secrets:
                file_warnings = file_warnings + check_file_for_secrets(file_path)

            if file_warnings:
                yield file_path, file_warnings


def check_directories(
    directories: list[str],
    check_secrets: bool = True,
) -> Generator[tuple[str, list[WarningInfo]], None, None]:
    """
    Обходит список директорий

    Args:
        directories:   список директорий для сканирования
        check_secrets: проверять содержимое файлов на секреты

    Yields:
        Кортеж (путь, список предупреждений)
    """
    for directory in directories:
        if os.path.exists(directory):
            yield from check_directory_files(directory, check_secrets)


def scan(
    arg: str | list[str],
    check_secrets: bool = True,
) -> Generator[tuple[str, list[WarningInfo]], None, None]:
    """
    Универсальный скан: принимает директорию или список директорий

    Args:
        arg:           директория или список директорий
        check_secrets: проверять содержимое файлов на секреты

    Yields:
        Кортеж (путь, список предупреждений)
    """

    paths = arg if isinstance(arg, list) else [arg]
    yield from check_directories(paths, check_secrets)
