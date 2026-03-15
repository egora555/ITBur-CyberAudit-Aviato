from GUIManager import GUIManager
import PermissionsCheck as Permissions
import AuditReporter
import NetworkAudit as Network
import PackageAudit as Package

import sys
import os

import datetime

from typing import NamedTuple, Callable, Any, Generator

class CommandInfo(NamedTuple):
    """Информация о команде"""
    func: Callable[..., Any]
    requires_params: bool

class App:
    """Приложение-аудитор"""

    argument_commands = {}
    argument_keywords = {}

    command_reports = {
        "scan": AuditReporter.report_permissions,
        "network": AuditReporter.report_network,
        "package": AuditReporter.report_package
    }

    output_file = None

    def __init__(self):
        # Было вынесено в __init__, так-как функции были недоступны
        self.argument_commands = {"scan" : CommandInfo(App.run_file_audit, True),
                                  "output" : CommandInfo(App.set_output, True),
                                  "network" : CommandInfo(App.run_network_audit, False),
                                  "package" : CommandInfo(App.run_package_audit, False),
                                  "help" : CommandInfo(App.help, False)}

        self.argument_keywords = self.argument_keywords = {"all" : Permissions.ROOT,
                                                           "user" : Permissions.USER_DIRECTORY,
                                                           "current" : Permissions.CURRENT_DIRECTORY,
                                                           "key" : Permissions.KEY_DIRECTORIES,
                                                           "key_dirs" : Permissions.KEY_DIRECTORIES,
                                                           "key_directories" : Permissions.KEY_DIRECTORIES}

        self.results = self.handle_args(self.get_args())

        self.gui_manager = GUIManager(self, "Auditor", window_size=(800, 600))

        self.gui_manager.create_gui()

        self.write_output(self.results)

        self.gui_manager.master.mainloop()

    def write_output(self, results: dict):
        """
        Запись результатов в файл
        Args:
            results (dict): результат команд
        """

        for command, result in results.items():
            command_output = self.command_reports.get(command.split("-")[0], None)
            if command_output is None:
                continue

            text = command_output(result)

            if self.output_file is None:
                print(text)
                continue

            self.write_output_file(command_output(result))

            # if command.startswith("scan"):
            #     self.write_output_file(AuditReporter.report_permissions(result))
            # elif command == "network":
            #     self.write_output_file(AuditReporter.report_network(result))
            #
            # elif command == "package":
            #     self.write_output_file(AuditReporter.report_package(result))


    def handle_args(self, args : list[str]) -> dict:
        """
        Обработка аргументов
        Args:
            args (list[str]): список аргументов

        Returns:
            dict: результаты всех команд
        """

        clean_args = [arg.lstrip("-") for arg in args]
        if "output" not in clean_args and ("scan" in clean_args or "network" in clean_args or "package" in clean_args):
            print("WARNING: файл вывода не указан!")
            should_continue = input("Для продолжения введите y/n (при продолжении результаты будут написаны в консоли): ")
            if should_continue in ["y", "yes", "true"]:
                print("Продолжение...")
            else:
                print("Отмена...")
                return {}

        results = {}

        i = 0

        while i < len(args):
            arg = args[i]

            is_command = arg.startswith('-')

            param = None

            if is_command:
                arg = arg.lstrip('-')
                command = self.argument_commands.get(arg, None)

                if command is None:
                    print(f"ERROR: аргумент {arg} не команда!")
                    return {}

                func = command.func
                require_params = command.requires_params

                if require_params:
                    if i + 1 >= len(args):
                        print(f"ERROR: параметры обязательны для команды {arg}!")
                        return {}

                    param = args[i + 1]

                    final_param = self.argument_keywords.get(param, None)

                    if final_param is None:
                        if not os.path.isabs(param):
                            param = os.path.abspath(param)

                        if os.path.exists(param):
                            final_param = param
                        else:
                            print(f"ERROR: параметр {param} не является ключевым словом/директорией/файлом!")
                            return {}

                    result = func(final_param)

                    i += 1

                else:
                    result = func()

                result_name = arg

                if require_params:
                    # Необходимо, что-бы не переопределять в словаре.
                    result_name = result_name + "-" + param

                results[result_name] = result

            else:
                print(f"ERROR: неизвестный аргумент {arg}!")
                return {}

            i += 1

        return results

    @classmethod
    def run_file_audit(cls, path : str) -> Generator:
        """
        Запуск файлого аудита (проверка на права и наличие секретов в файлах)

        Args:
            path (str): путь к директории

        Returns:
            Generator: результаты файлого аудита
        """

        print("Запуск файлового аудита...")
        results = Permissions.scan(path)

        return results

    @classmethod
    def run_package_audit(cls) -> dict:
        """
        Запуск аудита установленных пакетов

        Returns:
            dict: результаты аудита установленных пакетов
        """

        print("Запуск аудита установленных пакетов...")
        results = Package.audit_packages()

        return results

    @classmethod
    def run_network_audit(cls) -> dict:
        """
        Запуск сетевого аудита

        Returns:
            dict: результаты сетевого аудита
        """
        print("Запуск сетевого аудита...")
        results = Network.scan_network()

        return results

    @classmethod
    def set_output(cls, file: str):
        """
        Выводит результаты в отдельный файл

        Args:
            file (str): путь к файлу
        """
        if not os.path.isabs(file):
            file = os.path.abspath(file)

        cls.output_file = file
        print(f"Результаты будут выводиться в: {file}")

        new_session_text = f"\n\n{"-" * 80}\nНОВАЯ АУДИТ СЕССИЯ: {datetime.datetime.now()}\n{"-" * 80}\n"

        cls.write_output_file(new_session_text)

    @classmethod
    def write_output_file(cls, text : str):
        """
        Записывает в output_file текст

        Args:
            text (str): текст для записи в файл
        """
        if cls.output_file is None:
            return

        with open(cls.output_file, "a", encoding="utf-8") as f:
            f.write(text)

    @classmethod
    def run_command(cls, func, *args, **kwargs):
        """
        Обёртка для запуска функции (можно дополнить)

        Args:
            func: функция
            *args: Позиционные аргументы для функции
            **kwargs: Именованные аргументы для функции

        Returns:
            Результат функции
        """
        return func(*args, **kwargs)

    @classmethod
    def help(cls):
        print(AuditReporter.report_help())

    @classmethod
    def get_args(cls) -> list[str]:
        """
        Список всех аргументов, переданных при запуске программы

        Returns:
            list[str]: список аргументов
        """
        args = sys.argv[1:]

        return args

if __name__ == "__main__":
    App()