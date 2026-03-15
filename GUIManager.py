import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os


class GUIManager(tk.Frame):
    """GUI Manager"""

    def __init__(self, app, title: str, master=None, window_size: tuple = (500, 500)):
        super().__init__(master)

        self.pack(expand=True, fill=tk.BOTH)

        self.app = app

        self.master.title(title)

        self.place_window(window_size)

        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.widgets = {}

        # Импортируем AuditReporter здесь
        import AuditReporter
        self.AuditReporter = AuditReporter

    def get_screen_resolution(self) -> tuple:
        """Разрешение экрана"""
        return self.master.winfo_screenwidth(), self.master.winfo_screenheight()

    def place_window(self, window_size: tuple):
        """Размещает окно по центру"""
        resolution = self.get_screen_resolution()

        center_x = int(resolution[0] / 2 - window_size[0] / 2)
        center_y = int(resolution[1] / 2 - window_size[1] / 2 - 10)

        self.master.geometry(f"{window_size[0]}x{window_size[1]}+{center_x}+{center_y}")

    def create_gui(self):
        """Создание графического интерфейса"""

        # Основная область
        self.create_main_area()

        # Область вывода
        self.create_output_area()

    def create_main_area(self):
        """Создание основной области с элементами управления"""

        # Фрейм для элементов управления
        control_frame = ttk.LabelFrame(self, text="Управление аудитом", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # Строка для файлового аудита
        file_frame = ttk.Frame(control_frame)
        file_frame.pack(fill=tk.X, pady=5)

        ttk.Label(file_frame, text="Путь для сканирования:").pack(side=tk.LEFT, padx=5)

        self.path_var = tk.StringVar(value=os.getcwd())
        path_entry = ttk.Entry(file_frame, textvariable=self.path_var, width=50)
        path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        ttk.Button(file_frame, text="Обзор...",
                   command=self.browse_directory).pack(side=tk.LEFT, padx=5)

        # Строка для файла вывода
        output_frame = ttk.Frame(control_frame)
        output_frame.pack(fill=tk.X, pady=5)

        ttk.Label(output_frame, text="Файл для вывода:").pack(side=tk.LEFT, padx=5)

        self.output_file_var = tk.StringVar(value="")
        output_entry = ttk.Entry(output_frame, textvariable=self.output_file_var, width=50)
        output_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        ttk.Button(output_frame, text="Выбрать файл...",
                   command=self.browse_output_file).pack(side=tk.LEFT, padx=5)

        ttk.Button(output_frame, text="Очистить",
                   command=self.clear_output_file).pack(side=tk.LEFT, padx=5)

        # Кнопки для видов аудита
        buttons_frame = ttk.Frame(control_frame)
        buttons_frame.pack(fill=tk.X, pady=5)

        self.scan_button = ttk.Button(buttons_frame, text="Сканировать файлы",
                                      command=self.run_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.network_button = ttk.Button(buttons_frame, text="Сетевой аудит",
                                         command=self.run_network)
        self.network_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.package_button = ttk.Button(buttons_frame, text="Аудит пакетов",
                                         command=self.run_package)
        self.package_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Кнопка очистки
        ttk.Button(buttons_frame, text="Очистить вывод",
                   command=self.clear_output).pack(side=tk.LEFT, padx=5)

    def create_output_area(self):
        """Создание области для вывода результатов"""

        # Фрейм для вывода
        output_frame = ttk.LabelFrame(self, text="Результаты аудита", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Текстовое поле с прокруткой
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            font=("Courier", 10)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def browse_directory(self):
        """Открыть диалог выбора директории"""
        directory = filedialog.askdirectory(
            title="Выберите директорию для сканирования",
            initialdir=self.path_var.get()
        )
        if directory:
            self.path_var.set(directory)

    def browse_output_file(self):
        """Открыть диалог выбора файла для вывода"""
        file_path = filedialog.asksaveasfilename(
            title="Выберите файл для сохранения результатов",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.output_file_var.set(file_path)
            # Устанавливаем файл вывода в App
            self.app.set_output(file_path)
            self.add_output(f"Результаты будут сохраняться в: {file_path}\n")

    def clear_output_file(self):
        """Очистить поле файла вывода"""
        self.output_file_var.set("")
        # Сбрасываем файл вывода в App
        self.app.__class__.output_file = None
        self.add_output("Вывод в файл отключён\n")

    def run_scan(self):
        """Запуск файлового аудита"""
        path = self.path_var.get().strip()

        if not path:
            messagebox.showerror("Ошибка", "Укажите путь для сканирования")
            return

        if not os.path.exists(path):
            messagebox.showerror("Ошибка", f"Путь не существует: {path}")
            return

        self.clear_output()
        self.add_output("Запуск файлового аудита...\n")
        self.add_output(f"Сканирование: {path}\n\n")

        try:
            results = self.app.run_file_audit(path)
            report = self.AuditReporter.report_permissions(results)
            self.add_output(report)

            # Сохраняем в файл, если указан
            if self.app.output_file:
                self.app.write_output_file(report)
                self.add_output(f"\n[Сохранено в файл: {self.app.output_file}]\n")

            messagebox.showinfo("Готово", "Файловый аудит завершён")
        except Exception as e:
            self.add_output(f"Ошибка: {str(e)}\n")
            messagebox.showerror("Ошибка", str(e))

    def run_network(self):
        """Запуск сетевого аудита"""
        self.clear_output()
        self.add_output("Запуск сетевого аудита...\n")

        try:
            results = self.app.run_network_audit()
            report = self.AuditReporter.report_network(results)
            self.add_output(report)

            # Сохраняем в файл, если указан
            if self.app.output_file:
                self.app.write_output_file(report)
                self.add_output(f"\n[Сохранено в файл: {self.app.output_file}]\n")

            messagebox.showinfo("Готово", "Сетевой аудит завершён")
        except Exception as e:
            self.add_output(f"Ошибка: {str(e)}\n")
            messagebox.showerror("Ошибка", str(e))

    def run_package(self):
        """Запуск аудита пакетов"""
        self.clear_output()
        self.add_output("Запуск аудита установленных пакетов...\n")

        try:
            results = self.app.run_package_audit()
            report = self.AuditReporter.report_package(results)
            self.add_output(report)

            # Сохраняем в файл, если указан
            if self.app.output_file:
                self.app.write_output_file(report)
                self.add_output(f"\n[Сохранено в файл: {self.app.output_file}]\n")

            messagebox.showinfo("Готово", "Аудит пакетов завершён")
        except Exception as e:
            self.add_output(f"Ошибка: {str(e)}\n")
            messagebox.showerror("Ошибка", str(e))

    def add_output(self, text):
        """Добавление текста в область вывода"""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.master.update()

    def clear_output(self):
        """Очистка области вывода"""
        self.output_text.delete(1.0, tk.END)