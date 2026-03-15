import subprocess
import re
from typing import List, Dict, NamedTuple, Optional

# База знаний об опасных/устаревших сервисах
DANGEROUS_SERVICES = {
    20: {
        "name": "FTP-data",
        "risk": "HIGH",
        "description": "FTP data port - используется вместе с FTP. Сам по себе не опасен, но сигнализирует о наличии FTP.",
        "anonymous_check": False
    },
    21: {
        "name": "FTP",
        "risk": "HIGH",
        "description": "FTP передаёт данные и пароли в открытом виде. Рекомендуется использовать SFTP или FTPS.",
        "anonymous_check": True
    },
    22: {
        "name": "SSH",
        "risk": "MEDIUM",
        "description": "SSH сервер для удаленного управления. Убедитесь, что: 1) Используются SSH-ключи вместо паролей 2) Отключен вход для root 3) Установлен fail2ban",
        "anonymous_check": False
    },
    23: {
        "name": "Telnet",
        "risk": "CRITICAL",
        "description": "Telnet передаёт все данные (включая пароли) без шифрования. Используйте SSH вместо Telnet.",
        "anonymous_check": False
    },
    25: {
        "name": "SMTP",
        "risk": "MEDIUM",
        "description": "SMTP без шифрования может использоваться для спама. Рекомендуется использовать с TLS/SSL.",
        "anonymous_check": False
    },
    53: {
        "name": "DNS",
        "risk": "LOW",
        "description": "DNS сервер - убедитесь, что он не открытый резолвер (не отвечает на рекурсивные запросы извне).",
        "anonymous_check": False
    },
    80: {
        "name": "HTTP",
        "risk": "LOW",
        "description": "Обычный веб-сервер. Рекомендуется перенаправлять на HTTPS (порт 443).",
        "anonymous_check": False
    },
    110: {
        "name": "POP3",
        "risk": "HIGH",
        "description": "POP3 без шифрования передаёт пароли в открытом виде. Используйте POP3S.",
        "anonymous_check": False
    },
    111: {
        "name": "RPC",
        "risk": "MEDIUM",
        "description": "RPC порт - может использоваться для NFS. Проверьте необходимость.",
        "anonymous_check": False
    },
    143: {
        "name": "IMAP",
        "risk": "HIGH",
        "description": "IMAP без шифрования передаёт пароли в открытом виде. Используйте IMAPS.",
        "anonymous_check": False
    },
    443: {
        "name": "HTTPS",
        "risk": "INFO",
        "description": "Защищённый веб-сервер. Убедитесь, что сертификат действителен и используется современный протокол TLS.",
        "anonymous_check": False
    },
    445: {
        "name": "SMB",
        "risk": "CRITICAL",
        "description": "SMB (CIFS) - известная цель для вирусов-вымогателей (WannaCry). Закройте, если не требуется для сетевых папок.",
        "anonymous_check": True
    },
    465: {
        "name": "SMTPS",
        "risk": "LOW",
        "description": "SMTP с SSL/TLS - защищённая отправка почты. Убедитесь в правильности настроек.",
        "anonymous_check": False
    },
    512: {
        "name": "rexec",
        "risk": "CRITICAL",
        "description": "Устаревший удалённый доступ без шифрования. Используйте SSH.",
        "anonymous_check": False
    },
    513: {
        "name": "rlogin",
        "risk": "CRITICAL",
        "description": "Устаревший удалённый доступ без шифрования. Используйте SSH.",
        "anonymous_check": False
    },
    514: {
        "name": "rsh",
        "risk": "CRITICAL",
        "description": "Устаревший удалённый доступ без шифрования. Используйте SSH.",
        "anonymous_check": False
    },
    587: {
        "name": "SMTP Submission",
        "risk": "LOW",
        "description": "SMTP с STARTTLS - защищённая отправка почты. Убедитесь в наличии аутентификации.",
        "anonymous_check": True
    },
    631: {
        "name": "CUPS",
        "risk": "MEDIUM",
        "description": "Служба печати - если не используется принтер, закройте порт.",
        "anonymous_check": False
    },
    873: {
        "name": "rsync",
        "risk": "MEDIUM",
        "description": "Rsync без ограничений может позволить скачать любые файлы. Настройте модули read-only и ограничьте доступ по IP.",
        "anonymous_check": True
    },
    993: {
        "name": "IMAPS",
        "risk": "LOW",
        "description": "IMAP с SSL/TLS - защищённый доступ к почте. Убедитесь в правильности настроек.",
        "anonymous_check": False
    },
    995: {
        "name": "POP3S",
        "risk": "LOW",
        "description": "POP3 с SSL/TLS - защищённый доступ к почте. Убедитесь в правильности настроек.",
        "anonymous_check": False
    },
    1080: {
        "name": "SOCKS",
        "risk": "MEDIUM",
        "description": "SOCKS прокси - может использоваться для обхода ограничений. Если не используется как прокси-сервер, закройте.",
        "anonymous_check": True
    },
    1433: {
        "name": "MSSQL",
        "risk": "CRITICAL",
        "description": "Microsoft SQL Server - если открыт в интернет, цель для атак. Должен слушать только localhost.",
        "anonymous_check": False
    },
    1521: {
        "name": "Oracle",
        "risk": "CRITICAL",
        "description": "Oracle DB - базы данных не должны быть доступны извне. Должна слушать только localhost.",
        "anonymous_check": False
    },
    2049: {
        "name": "NFS",
        "risk": "HIGH",
        "description": "NFS - сетевая файловая система без шифрования. Используйте NFSv4 с Kerberos и ограничьте доступ по IP.",
        "anonymous_check": True
    },
    2082: {
        "name": "cPanel",
        "risk": "MEDIUM",
        "description": "cPanel - панель управления хостингом. Убедитесь в сложности паролей и используйте HTTPS.",
        "anonymous_check": False
    },
    2083: {
        "name": "cPanel SSL",
        "risk": "LOW",
        "description": "cPanel с HTTPS - панель управления. Убедитесь в актуальности сертификата.",
        "anonymous_check": False
    },
    2222: {
        "name": "Alternative SSH",
        "risk": "MEDIUM",
        "description": "Альтернативный порт SSH. Те же рекомендации, что и для порта 22.",
        "anonymous_check": False
    },
    3306: {
        "name": "MySQL/MariaDB",
        "risk": "CRITICAL",
        "description": "База данных MySQL/MariaDB - если видите этот порт, проверьте что он слушает только localhost (127.0.0.1). Никогда не открывайте базу данных в интернет!",
        "anonymous_check": False
    },
    3389: {
        "name": "RDP",
        "risk": "CRITICAL",
        "description": "Remote Desktop Protocol - частая цель для брутфорс-атак. Используйте VPN для доступа к RDP.",
        "anonymous_check": False
    },
    5432: {
        "name": "PostgreSQL",
        "risk": "CRITICAL",
        "description": "PostgreSQL - база данных должна слушать только localhost. Никогда не открывайте в интернет!",
        "anonymous_check": False
    },
    5900: {
        "name": "VNC",
        "risk": "CRITICAL",
        "description": "VNC - часто без пароля или со слабым паролем. Используйте SSH-туннель для VNC.",
        "anonymous_check": True
    },
    5901: {
        "name": "VNC-1",
        "risk": "CRITICAL",
        "description": "VNC :1 - часто без пароля или со слабым паролем. Используйте SSH-туннель.",
        "anonymous_check": True
    },
    6379: {
        "name": "Redis",
        "risk": "CRITICAL",
        "description": "Redis без пароля - частая причина взломов. Настройте пароль и bind 127.0.0.1",
        "anonymous_check": True
    },
    8080: {
        "name": "HTTP-Alt",
        "risk": "LOW",
        "description": "Альтернативный HTTP порт (часто используется для прокси или tomcat). Проверьте необходимость.",
        "anonymous_check": False
    },
    8443: {
        "name": "HTTPS-Alt",
        "risk": "LOW",
        "description": "Альтернативный HTTPS порт (Plesk, tomcat). Проверьте сертификат.",
        "anonymous_check": False
    },
    9200: {
        "name": "Elasticsearch",
        "risk": "CRITICAL",
        "description": "Elasticsearch без аутентификации - частая причина утечек данных. Настройте безопасность!",
        "anonymous_check": True
    },
    27017: {
        "name": "MongoDB",
        "risk": "CRITICAL",
        "description": "MongoDB без аутентификации - одна из главных причин утечек данных. Всегда включайте авторизацию и слушайте localhost!",
        "anonymous_check": True
    },
    27018: {
        "name": "MongoDB",
        "risk": "CRITICAL",
        "description": "MongoDB shard - без аутентификации очень опасно.",
        "anonymous_check": True
    },
    50000: {
        "name": "SAP",
        "risk": "HIGH",
        "description": "SAP NetWeaver - корпоративная система. Убедитесь в надёжности аутентификации.",
        "anonymous_check": False
    }
}


class PortInfo(NamedTuple):
    """Информация об открытом порте"""
    protocol: str  # tcp/udp
    port: int
    address: str
    process: Optional[str]
    pid: Optional[int]

    def is_local_only(self) -> bool:
        """Проверяет, слушает ли порт только localhost"""
        return self.address == '127.0.0.1' or self.address == '::1'

    def is_public(self) -> bool:
        """Проверяет, доступен ли порт извне"""
        return self.address == '0.0.0.0' or self.address == '::' or self.address == '*'


class NetworkWarning(NamedTuple):
    """Информация о предупреждении сетевого аудита"""
    message: str
    level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    code: str
    port: int
    protocol: str
    process: Optional[str]

    def __str__(self) -> str:
        """Строковое представление предупреждения"""
        return f"[{self.level}] Порт {self.port}/{self.protocol} ({self.process}): {self.message}"

    def to_dict(self) -> dict:
        """Преобразование в словарь для сериализации"""
        return {
            "code": self.code,
            "level": self.level,
            "message": self.message,
            "port": self.port,
            "protocol": self.protocol,
            "process": self.process
        }


def run_ss_command() -> Optional[str]:
    """
    Запускает команду ss -tulpn и возвращает её вывод

    Returns:
        Optional[str]: вывод команды или None в случае ошибки
    """
    try:
        commands = [
            ['sudo', 'ss', '-tulpn'],
            ['ss', '-tulpn']
        ]

        print("Примечание: для сетевого аудита требуется права root.")
        print("Запуск с sudo... (может потребоваться пароль)")

        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout
            except (subprocess.SubprocessError, FileNotFoundError):
                continue

        print("ERROR: Не удалось выполнить команду ss. Убедитесь, что iproute2 установлен.")
        return None

    except Exception as e:
        print(f"ERROR: Ошибка при выполнении ss: {e}")
        return None


def parse_ss_output(output: str) -> List[PortInfo]:
    """
    Парсит вывод команды ss -tulpn

    Args:
        output (str): вывод команды ss

    Returns:
        List[PortInfo]: список информации об открытых портах
    """
    ports = []

    # Регулярное выражение для парсинга строки ss
    pattern = r'^(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+\s+\S*\s*(?:users:\(\([^)]+\)\))?'

    lines = output.strip().split('\n')

    # Пропускаем заголовок
    for line in lines[1:]:
        if not line.strip():
            continue

        process_match = re.search(r'users:\(\(\"([^"]+)\",pid=(\d+)', line)
        process = process_match.group(1) if process_match else None
        pid = int(process_match.group(2)) if process_match else None

        match = re.match(pattern, line)
        if match:
            protocol = match.group(1)
            address = match.group(2)
            port = int(match.group(3))

            if address == '*':
                address = '0.0.0.0'
            elif address == '::':
                address = '0.0.0.0'

            ports.append(PortInfo(
                protocol=protocol,
                port=port,
                address=address,
                process=process,
                pid=pid
            ))

    return ports


def analyze_ports(ports: List[PortInfo]) -> List[NetworkWarning]:
    """
    Анализирует открытые порты на основе базы знаний

    Args:
        ports (List[PortInfo]): список открытых портов

    Returns:
        List[NetworkWarning]: список предупреждений
    """
    warnings = []
    processed_ports = set()  # Множество для отслеживания уже обработанных портов

    for port_info in ports:
        port_key = f"{port_info.port}/{port_info.protocol}"

        if port_info.port in DANGEROUS_SERVICES:
            service = DANGEROUS_SERVICES[port_info.port]

            if port_info.port in [3306, 5432, 27017, 6379]:
                if port_info.is_public():
                    level = "CRITICAL"
                    message = f"{service['name']} доступна извне! Это очень опасно. Должна слушать только localhost (127.0.0.1)."

                    warnings.append(NetworkWarning(
                        message=message,
                        level=level,
                        code=f"PORT-{port_info.port}",
                        port=port_info.port,
                        protocol=port_info.protocol,
                        process=port_info.process
                    ))

                elif port_info.is_local_only():
                    # Если порт уже обработан, не добавляем повторно INFO сообщение
                    if port_key not in processed_ports:
                        level = "INFO"
                        message = f"{service['name']} слушает localhost - правильно настроено."

                        warnings.append(NetworkWarning(
                            message=message,
                            level=level,
                            code=f"PORT-{port_info.port}",
                            port=port_info.port,
                            protocol=port_info.protocol,
                            process=port_info.process
                        ))
                else:
                    # Если порт уже обработан, не добавляем повторно
                    if port_key not in processed_ports:
                        level = "MEDIUM"
                        message = f"{service['name']} на адресе {port_info.address} - убедитесь, что это правильно."

                        warnings.append(NetworkWarning(
                            message=message,
                            level=level,
                            code=f"PORT-{port_info.port}",
                            port=port_info.port,
                            protocol=port_info.protocol,
                            process=port_info.process
                        ))
            else:
                # Для остальных сервисов добавляем только одно предупреждение на порт
                if port_key not in processed_ports:
                    level = service['risk']
                    message = service['description']

                    warnings.append(NetworkWarning(
                        message=message,
                        level=level,
                        code=f"PORT-{port_info.port}",
                        port=port_info.port,
                        protocol=port_info.protocol,
                        process=port_info.process
                    ))

            # Помечаем порт как обработанный
            processed_ports.add(port_key)

        # Проверяем другие потенциальные проблемы (только если порт ещё не обработан)
        else:
            if port_key not in processed_ports:
                # Неизвестный сервис
                if port_info.is_public():
                    warnings.append(NetworkWarning(
                        message=f"Неизвестный сервис на порту {port_info.port} доступен извне. Проверьте необходимость.",
                        level="MEDIUM",
                        code=f"PORT-{port_info.port}-UNKNOWN",
                        port=port_info.port,
                        protocol=port_info.protocol,
                        process=port_info.process
                    ))

                # Системные порты (ниже 1024) требуют внимания
                if port_info.port < 1024 and port_info.is_public():
                    warnings.append(NetworkWarning(
                        message=f"Привилегированный порт {port_info.port} открыт наружу. Убедитесь, что это необходимо.",
                        level="LOW",
                        code=f"PORT-{port_info.port}-PRIV",
                        port=port_info.port,
                        protocol=port_info.protocol,
                        process=port_info.process
                    ))

                processed_ports.add(port_key)

    return warnings


def scan_network() -> Dict[str, List[NetworkWarning]]:
    """
    Основная функция для сканирования сети

    Returns:
        Dict[str, List[NetworkWarning]]: результаты анализа в формате {порт: список_предупреждений}
    """
    result = {}

    output = run_ss_command()
    if not output:
        return {"error": [NetworkWarning(
            message="Не удалось получить информацию о сетевых портах",
            level="ERROR",
            code="NETWORK-SCAN-ERROR",
            port=0,
            protocol="unknown",
            process=None
        )]}

    ports = parse_ss_output(output)

    warnings = analyze_ports(ports)

    for warning in warnings:
        key = f"{warning.port}/{warning.protocol}"
        if key not in result:
            result[key] = []
        result[key].append(warning)

    return result