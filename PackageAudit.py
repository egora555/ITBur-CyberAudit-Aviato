import subprocess
import os
from datetime import datetime

# Важные пакеты для аудита
TARGET_PACKAGES = ['nginx', 'apache2', 'mysql', 'mariadb', 'openssh', 'ssh', 'linux-image', 'kernel']

# Имитация базы данных, так как для реальных баз данных уязвимостей нужны API ключи
MOCK_CVE_DB = {
    'openssh': {
        '1:9.2p1-2': ['CVE-2023-1234', 'CVE-2023-5678'],
        '1:8.9p1-3': ['CVE-2023-1234'],
        '1:8.4p1-5': ['CVE-2022-9876', 'CVE-2022-5432'],
    },
    'ssh': {
        '1:9.2p1-2': ['CVE-2023-1234', 'CVE-2023-5678'],
    },
    'nginx': {
        '1.22.1': ['CVE-2023-44487'],
        '1.18.0': ['CVE-2021-23017', 'CVE-2022-41741'],
    },
    'apache2': {
        '2.4.57': ['CVE-2023-31122'],
        '2.4.52': ['CVE-2022-31813', 'CVE-2022-36760'],
    },
    'mysql-server': {
        '8.0.33': ['CVE-2023-21911', 'CVE-2023-21912'],
        '5.7.42': ['CVE-2022-21594', 'CVE-2022-21595'],
    },
    'mariadb-server': {
        '10.11.2': ['CVE-2023-22084'],
    },
    'linux-image': {
        '6.1.0': ['CVE-2023-2345', 'CVE-2023-6789'],
        '5.10.0': ['CVE-2022-1234', 'CVE-2022-5678'],
    },
    'linux-image-amd64': {
        '6.1.0': ['CVE-2023-2345', 'CVE-2023-6789'],
    },
}


def _get_system_info() -> dict[str, str]:
    """
    Получение информации о системе

    Returns:
        Dict[str, str]: словарь с информацией (hostname, kernel, os, date)
    """
    info = {
        'hostname': 'unknown',
        'kernel': 'unknown',
        'os': 'unknown',
        'date': datetime.now().isoformat()
    }

    try:
        result = subprocess.run(['hostname'], capture_output=True, text=True)
        if result.returncode == 0:
            info['hostname'] = result.stdout.strip()

        result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
        if result.returncode == 0:
            info['kernel'] = result.stdout.strip()

        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        info['os'] = line.split('=')[1].strip().strip('"')
                        break
    except:
        pass

    return info


def _get_installed_packages() -> list[dict[str, str]]:
    """
    Получение списка установленных пакетов через dpkg

    Returns:
        List[Dict[str, str]]: список пакетов с полями name и version
    """
    packages = []

    try:
        result = subprocess.run(
            ['dpkg-query', '-W', '-f=${Package} ${Version}\n'],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line and ' ' in line:
                    parts = line.strip().split(' ', 1)
                    if len(parts) == 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1]
                        })
    except:
        pass

    return packages


def _check_service_status(service: str) -> str:
    """
    Проверка статуса сервиса через systemctl

    Args:
        service (str): имя сервиса

    Returns:
        str: статус сервиса (active/inactive/unknown)
    """
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except:
        return "unknown"


def _check_vulnerabilities(package_name: str, version: str) -> list[str]:
    """
    Проверка пакета на известные уязвимости

    Args:
        package_name (str): имя пакета
        version (str): версия пакета

    Returns:
        List[str]: список CVE идентификаторов
    """
    package_lower = package_name.lower()

    if package_lower in MOCK_CVE_DB:
        for ver_pattern, cves in MOCK_CVE_DB[package_lower].items():
            if version.startswith(ver_pattern) or ver_pattern in version:
                return cves

    for pkg_pattern, versions in MOCK_CVE_DB.items():
        if pkg_pattern in package_lower:
            for ver_pattern, cves in versions.items():
                if version.startswith(ver_pattern) or ver_pattern in version:
                    return cves

    return []


def _filter_target_packages(packages: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    Фильтрация пакетов по целевому списку TARGET_PACKAGES

    Args:
        packages (List[Dict[str, str]]): список всех пакетов

    Returns:
        List[Dict[str, str]]: отфильтрованные пакеты
    """
    filtered = []
    for pkg in packages:
        pkg_lower = pkg['name'].lower()
        for target in TARGET_PACKAGES:
            if target in pkg_lower:
                filtered.append(pkg)
                break
    return filtered


def audit_packages() -> dict:
    """
    Основная функция аудита пакетов

    Returns:
        Dict: результаты аудита со структурой:
            - system: информация о системе
            - packages: список целевых пакетов
            - vulnerabilities: список уязвимостей
            - services: статусы сервисов
            - summary: сводная статистика
    """
    results = {
        'system': _get_system_info(),
        'packages': [],
        'vulnerabilities': [],
        'services': {},
        'summary': {
            'total_packages': 0,
            'target_packages': 0,
            'vulnerable_packages': 0,
            'total_cves': 0
        }
    }

    all_packages = _get_installed_packages()
    results['summary']['total_packages'] = len(all_packages)

    if not all_packages:
        return results

    target_pkgs = _filter_target_packages(all_packages)
    results['summary']['target_packages'] = len(target_pkgs)

    for pkg in target_pkgs:
        pkg_info = {
            'name': pkg['name'],
            'version': pkg['version']
        }

        cves = _check_vulnerabilities(pkg['name'], pkg['version'])
        if cves:
            pkg_info['vulnerable'] = True
            pkg_info['cves'] = cves
            results['vulnerabilities'].append({
                'package': pkg['name'],
                'version': pkg['version'],
                'cves': cves
            })
            results['summary']['vulnerable_packages'] += 1
            results['summary']['total_cves'] += len(cves)

        results['packages'].append(pkg_info)

        service_name = pkg['name'].split('/')[0].split('-')[0]
        if service_name in ['nginx', 'apache2', 'mysql', 'ssh', 'openssh']:
            status = _check_service_status(service_name)
            results['services'][service_name] = status

    kernel_version = results['system']['kernel']
    kernel_cves = _check_vulnerabilities('linux-image', kernel_version)
    if kernel_cves:
        kernel_already_added = any(
            v['package'] == 'linux-image' for v in results['vulnerabilities']
        )
        if not kernel_already_added:
            results['vulnerabilities'].append({
                'package': 'linux-image',
                'version': kernel_version,
                'cves': kernel_cves
            })
            results['summary']['vulnerable_packages'] += 1
            results['summary']['total_cves'] += len(kernel_cves)

    return results


def save_results_to_file(results: dict, filename: str = None) -> str:
    """
    Сохранение результатов в JSON файл

    Args:
        results (Dict): результаты аудита
        filename (str, optional): имя файла. Если не указано, генерируется автоматически

    Returns:
        str: путь к сохранённому файлу или пустая строка при ошибке
    """
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"package_audit_{timestamp}.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            import json
            json.dump(results, f, indent=2, ensure_ascii=False)
        return filename
    except:
        return ""

def get_vulnerable_packages(results: dict) -> list[dict]:
    """
    Получение списка уязвимых пакетов из результатов

    Args:
        results (Dict): результаты аудита

    Returns:
        List[Dict]: список уязвимых пакетов
    """
    return results.get('vulnerabilities', [])

def is_system_vulnerable(results: dict) -> bool:
    """
    Проверка, есть ли уязвимости в системе

    Args:
        results (Dict): результаты аудита

    Returns:
        bool: True если есть уязвимости
    """
    return len(results.get('vulnerabilities', [])) > 0