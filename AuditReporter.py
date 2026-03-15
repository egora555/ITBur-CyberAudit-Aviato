from PermissionsCheck import WarningInfo

# Рекомендации для файлового аудита
SUGGESTIONS = {
    "PERM-777": "Уберите полные права для всех пользователей. Рекомендуется установить chmod 755 для директорий или chmod 644 для обычных файлов.",
    "PERM-666": "Файл доступен на запись всем пользователям. Рекомендуется убрать запись для 'others': chmod 644 <file>.",
    "PERM-WORLD-WRITE": "Любой пользователь может изменять файл. Уберите право записи для остальных пользователей: chmod o-w <file>.",
    "PERM-SUID": "У файла установлен SUID. Если это не требуется, удалите его: chmod u-s <file>. Проверьте необходимость запуска файла с правами владельца.",
    "PERM-SGID": "У файла установлен SGID. Если это не требуется, удалите его: chmod g-s <file>. Проверьте необходимость запуска с правами группы.",
    "PERM-STICKY": "Установлен sticky bit. Обычно используется для общих директорий (например /tmp). Убедитесь, что это действительно необходимо.",
    "PERM-GROUP-RW": "Группа имеет права чтения и записи. Если файл содержит чувствительные данные, рекомендуется ограничить доступ: chmod 640 или chmod 600.",

    "PERM-SECRET-IN-FILE": "Файл содержит секретные данные и доступен всем на чтение! Закройте доступ: chmod 640 <file>. И удалите секреты из файла, используйте переменные окружения.",
    "PERM-PASSWORD-IN-FILE": "В файле найден пароль в открытом виде. Удалите пароль и используйте переменные окружения или специальные файлы конфигурации с ограниченным доступом.",
    "PERM-SSH-KEY-WORLD-READABLE": "Приватный SSH ключ доступен всем на чтение! Это критическая уязвимость. Исправьте: chmod 600 <file>",
    "PERM-WORLD-READABLE-SENSITIVE": "Конфиденциальный файл доступен на чтение всем пользователям. Ограничьте доступ: chmod 640 <file> или chmod 600 <file>",
    "PERM-WORLD-READABLE": "Файл доступен на чтение всем. Если это не общедоступный файл, ограничьте доступ: chmod o-r <file>",
    "PERM-ERROR": "Ошибка доступа к файлу. Проверьте, существует ли файл и есть ли права на чтение.",

    "SECRET-FOUND": "Обнаружен открытый секрет (ключ, пароль, токен) в файле. Немедленно прекратите его использование, отзовите (revoke) ключ у провайдера, удалите секрет из файла/истории и замените его на переменную окружения или менеджер секретов."
}

# Рекомендации для сетевого аудита
NETWORK_SUGGESTIONS = {
    "PORT-21": "Закройте FTP или перейдите на SFTP/FTPS. Для закрытия: sudo ufw deny 21",
    "PORT-22": "Настройте SSH безопасно: 1) Используйте ключи вместо паролей 2) Отключите вход для root 3) Установите fail2ban",
    "PORT-23": "Telnet крайне опасен! Закройте порт и используйте SSH: sudo ufw deny 23",
    "PORT-80": "Настройте HTTPS с Let's Encrypt: sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx",
    "PORT-443": "Проверьте срок действия SSL сертификата: sudo certbot certificates",
    "PORT-3306": "MySQL/MariaDB не должен быть доступен извне! В конфиге установите bind-address = 127.0.0.1",
    "PORT-5432": "PostgreSQL не должен быть доступен извне! В postgresql.conf установите listen_addresses = 'localhost'",
    "PORT-27017": "MongoDB не должен быть доступен извне! В mongod.conf установите bindIp: 127.0.0.1 и включите авторизацию",
    "PORT-6379": "Redis не должен быть доступен извне! В redis.conf установите bind 127.0.0.1 и requirepass пароль",
    "PORT-3389": "RDP не должен быть открыт в интернет. Используйте VPN для доступа или ограничьте по IP",
    "PORT-5900": "VNC небезопасен без SSH туннеля. Используйте: ssh -L 5901:localhost:5900 user@server",
    "PORT-445": "SMB критически опасен в интернете! Немедленно закройте: sudo ufw deny 445",
}

# Рекомендации для аудита пакетов
PACKAGE_SUGGESTIONS = {
    "CVE-2023-1234": "Обновите пакет до последней версии: sudo apt update && sudo apt upgrade <package>",
    "CVE-2023-5678": "Обновите пакет до последней версии: sudo apt update && sudo apt upgrade <package>",
    "CVE-2022-9876": "Обновите пакет до последней версии: sudo apt update && sudo apt upgrade <package>",
    "CVE-2022-5432": "Обновите пакет до последней версии: sudo apt update && sudo apt upgrade <package>",
    "CVE-2023-44487": "Обновите nginx до версии 1.24.0 или выше: sudo apt update && sudo apt upgrade nginx",
    "CVE-2021-23017": "Обновите nginx до версии 1.20.1 или выше: sudo apt update && sudo apt upgrade nginx",
    "CVE-2022-41741": "Обновите nginx до версии 1.22.1 или выше: sudo apt update && sudo apt upgrade nginx",
    "CVE-2023-31122": "Обновите apache2 до версии 2.4.58 или выше: sudo apt update && sudo apt upgrade apache2",
    "CVE-2022-31813": "Обновите apache2 до версии 2.4.54 или выше: sudo apt update && sudo apt upgrade apache2",
    "CVE-2022-36760": "Обновите apache2 до версии 2.4.55 или выше: sudo apt update && sudo apt upgrade apache2",
    "CVE-2023-21911": "Обновите mysql-server до версии 8.0.34 или выше: sudo apt update && sudo apt upgrade mysql-server",
    "CVE-2023-21912": "Обновите mysql-server до версии 8.0.34 или выше: sudo apt update && sudo apt upgrade mysql-server",
    "CVE-2022-21594": "Обновите mysql-server до версии 5.7.43 или выше: sudo apt update && sudo apt upgrade mysql-server",
    "CVE-2022-21595": "Обновите mysql-server до версии 5.7.43 или выше: sudo apt update && sudo apt upgrade mysql-server",
    "CVE-2023-22084": "Обновите mariadb-server до версии 10.11.3 или выше: sudo apt update && sudo apt upgrade mariadb-server",
    "CVE-2022-27376": "Обновите mariadb-server до версии 10.5.19 или выше: sudo apt update && sudo apt upgrade mariadb-server",
    "CVE-2022-27377": "Обновите mariadb-server до версии 10.5.19 или выше: sudo apt update && sudo apt upgrade mariadb-server",
    "CVE-2023-2345": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2023-6789": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2023-4567": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2022-1234": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2022-5678": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2022-9012": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2021-1234": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2021-5678": "Обновите ядро Linux: sudo apt update && sudo apt upgrade linux-image-$(uname -r)",
    "CVE-2021-28041": "Обновите openssh-server: sudo apt update && sudo apt upgrade openssh-server",
    "CVE-2020-15778": "Обновите openssh-server: sudo apt update && sudo apt upgrade openssh-server",
    "CVE-2017-7529": "Обновите nginx: sudo apt update && sudo apt upgrade nginx",
    "CVE-2021-44790": "Обновите apache2: sudo apt update && sudo apt upgrade apache2",
    "CVE-2020-11984": "Обновите apache2: sudo apt update && sudo apt upgrade apache2",
    "CVE-2019-2737": "Обновите mysql-server: sudo apt update && sudo apt upgrade mysql-server",
    "CVE-2020-2922": "Обновите mysql-server: sudo apt update && sudo apt upgrade mysql-server",
}

# Вспомогательная линия
DIVISION_LINE = "-" * 80

def header(text : str) -> list:
    """
    Заголовок

    Args:
        text (str): текст для заголовка

    Returns:
        list: список из 3 элементов: [1_черта, заголовок, 2_черта]
    """

    return [DIVISION_LINE, text, DIVISION_LINE]

def report_permissions(results: dict[str, list[WarningInfo]]) -> str:
    """
    Формат результатов сканирования прав

    Args:
        results (dict[str, list[WarningInfo]]): результаты сканирования

    Returns:
        str: результаты сканирования
    """

    if not results:
        return "Нет предупреждений."

    output_lines = header("ОТЧЁТ О ПРОВЕРКЕ ПРАВ ДОСТУПА")
    total_warnings = 0
    level_counts = {}

    for path, warnings in results:
        output_lines.append(f"\nФайл: {path}")
        for warning in warnings:
            total_warnings += 1
            level_counts[warning.level] = level_counts.get(warning.level, 0) + 1

            output_lines.append(f"   [{warning.level}] {warning.message}")
            suggestion = SUGGESTIONS.get(warning.code)
            if suggestion:
                output_lines.append(f"      Рекомендация: {suggestion}")

    output_lines.extend(header("РЕЗУЛЬТАТЫ ПРОВЕРКИ ПРАВ"))

    output_lines.append(f"Всего предупреждений: {total_warnings}")
    for level, count in level_counts.items():
        output_lines.append(f"   {level}: {count}")

    output_lines.append("\n")

    return "\n".join(output_lines)


def report_network(results: dict) -> str:
    """
    Формирует отчёт по сетевому аудиту

    Args:
        results: результаты сетевого сканирования

    Returns:
        str: отчёт
    """

    if not results:
        return "Нет открытых сетевых портов или не удалось получить информацию."

    output_lines = header("ОТЧЁТ СЕТЕВОГО АУДИТА")

    if "error" in results:
        output_lines.append(f"\nОШИБКА: {results['error'][0].message}")
        return "\n".join(output_lines)

    total_ports = len(results)
    level_counts = {}

    for port_key, warnings in results.items():
        port, protocol = port_key.split('/')
        output_lines.append(f"\nПорт: {port}/{protocol}")

        for warning in warnings:
            level_counts[warning.level] = level_counts.get(warning.level, 0) + 1

            output_lines.append(f"   [{warning.level}] {warning.message}")
            if warning.process:
                output_lines.append(f"      Процесс: {warning.process}")

            suggestion = NETWORK_SUGGESTIONS.get(warning.code)
            if suggestion:
                output_lines.append(f"      Рекомендация: {suggestion}")

    output_lines.extend(header("РЕЗУЛЬТАТЫ СЕТЕВОГО АУДИТА"))

    output_lines.append(f"Всего портов: {total_ports}")
    for level, count in level_counts.items():
        output_lines.append(f"   {level}: {count}")

    output_lines.append("\n")

    return "\n".join(output_lines)

def report_package(results: dict) -> str:
    """
    Форматирует отчёт по аудиту пакетов

    Args:
        results (dict): результаты аудита пакетов

    Returns:
        str: отчёт
    """

    if not results:
        return "Не удалось получить результаты аудита пакетов."

    if "error" in results:
        return f"ОШИБКА: {results['error']}"

    output_lines = header("ОТЧЁТ АУДИТА УСТАНОВЛЕННЫХ ПАКЕТОВ")

    system = results.get('system', {})
    output_lines.append(f"\nСистема:")
    output_lines.append(f"   Хост: {system.get('hostname', 'N/A')}")
    output_lines.append(f"   ОС: {system.get('os', 'N/A')}")
    output_lines.append(f"   Ядро: {system.get('kernel', 'N/A')}")
    output_lines.append(f"   Дата: {system.get('date', 'N/A')}")

    services = results.get('services', {})
    if services:
        output_lines.append(f"\nСтатус сервисов:")
        for service, status in services.items():
            output_lines.append(f"   {service}: {status}")

    vulnerabilities = results.get('vulnerabilities', [])
    if vulnerabilities:
        output_lines.append(f"\nНайдено уязвимостей: {len(vulnerabilities)}")
        for vuln in vulnerabilities:
            output_lines.append(f"\n   Пакет: {vuln['package']}")
            output_lines.append(f"   Версия: {vuln['version']}")
            cves = vuln.get('cves', [])
            output_lines.append(f"   CVE: {', '.join(cves)}")
            for cve in cves:
                suggestion = PACKAGE_SUGGESTIONS.get(cve)
                if suggestion:
                    suggestion_text = suggestion.replace('<package>', vuln['package'].split('/')[0])
                    output_lines.append(f"      Рекомендация: {suggestion_text}")
    else:
        output_lines.append(f"\nУязвимостей не найдено")

    summary = results.get('summary', {})
    output_lines.extend(header("РЕЗУЛЬТАТЫ АУДИТА ПАКЕТОВ"))
    output_lines.append(f"Всего пакетов в системе: {summary.get('total_packages', 0)}")
    output_lines.append(f"Проверено пакетов: {summary.get('target_packages', 0)}")
    output_lines.append(f"Уязвимых пакетов: {summary.get('vulnerable_packages', 0)}")
    output_lines.append(f"Всего найдено CVE: {summary.get('total_cves', 0)}")

    output_lines.append("\n")

    return "\n".join(output_lines)


def report_help() -> str:
    """
    Формирует справочную информацию по использованию программы

    Returns:
        str: справочное сообщение
    """
    output_lines = header("АУДИТОР БЕЗОПАСНОСТИ v1.0")

    output_lines.append("")
    output_lines.append("ИСПОЛЬЗОВАНИЕ:")
    output_lines.append("    python Auditor.py [КОМАНДЫ] [КЛЮЧЕВЫЕ_СЛОВА]")
    output_lines.append("    python Auditor.py                     # Запуск графического интерфейса")
    output_lines.append("")

    output_lines.append("КОМАНДЫ:")
    output_lines.append("    -scan [путь/ключ]    Сканирование прав доступа и поиск секретов")
    output_lines.append("    -network             Сетевой аудит (сканирование открытых портов)")
    output_lines.append("    -package             Аудит установленных пакетов и проверка CVE")
    output_lines.append("    -output [файл]       Сохранение результатов в указанный файл")
    output_lines.append("    -help, --help, -h    Показать эту справку")
    output_lines.append("")

    output_lines.append("КЛЮЧЕВЫЕ СЛОВА ДЛЯ -scan:")
    output_lines.append("    all                  Сканирование всей системы (корневая директория /)")
    output_lines.append("    user                 Сканирование домашней директории пользователя")
    output_lines.append("    current              Сканирование текущей директории")
    output_lines.append("    key, key_dirs,       Сканирование ключевых директорий")
    output_lines.append("    key_directories      (/etc, /var, /home)")
    output_lines.append("    /путь/к/папке        Сканирование конкретной директории")
    output_lines.append("")

    output_lines.append("ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:")
    output_lines.append("    python Auditor.py -scan key                          # Сканировать /etc, /var, /home")
    output_lines.append("    python Auditor.py -scan /var/www                     # Сканировать конкретную папку")
    output_lines.append("    python Auditor.py -network                           # Только сетевой аудит")
    output_lines.append("    python Auditor.py -package                           # Только аудит пакетов")
    output_lines.append("    python Auditor.py -scan key -network -package        # Полный аудит")
    output_lines.append("    python Auditor.py -scan all -output report.txt       # Сканировать всё и сохранить")
    output_lines.append(
        "    sudo python Auditor.py -network                      # Сетевое сканирование с правами root")
    output_lines.append("")

    output_lines.append("ПРИМЕЧАНИЯ:")
    output_lines.append("    • Для полного сетевого аудита рекомендуются права root (sudo)")
    output_lines.append("    • Аудит пакетов работает только на Debian-системах (использует dpkg)")
    output_lines.append("    • Программа тестировалась на Kali Linux и Python 3.12")
    output_lines.append("")

    return "\n".join(output_lines)