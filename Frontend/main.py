import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QLineEdit
import requests

from Frontend.output import Ui_MainWindow
import settings


class MyApp(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        # Настройки
        self.setWindowTitle(settings.APP_TITLE)
        self.setMinimumSize(settings.MIN_WIDTH, settings.MIN_HEIGHT)


        self.stackedWidget.setCurrentIndex(0)


        # Подсказки
        self.login_edit.setPlaceholderText(settings.LOGIN_PLACEHOLDER)
        self.password_edit.setPlaceholderText(settings.PASS_PLACEHOLDER)
        self.login_edit_2.setPlaceholderText("Придумайте логин")
        self.password_edit_2.setPlaceholderText("Придумайте пароль")
        self.password_edit_3.setPlaceholderText("Повторите пароль")

        # Подсказки при наведении
        self.register_button.setToolTip("Нажмите, чтобы создать новый аккаунт")

        # Скрытие паролей
        self.password_edit.setEchoMode(self.password_edit.Password)
        self.password_edit_2.setEchoMode(self.password_edit.Password)
        self.password_edit_3.setEchoMode(self.password_edit.Password)

        # Тексты

        self.text_label_2.setText('Нет аккаунта? Зарегистрируйтесь:')
        self.text_label_4.setText('Пароль несоответствует требованиям.')

        # Чекбоксы

        self.checkBox.setText('Показать пароль') # Чекбокс 1 - Страница авторизации
        self.checkBox_2.setText('Показать пароль')  # Чекбокс 2 - Страница регистрации

        if hasattr(self, 'checkBox'):
            self.checkBox.stateChanged.connect(self.toggle_password_visibility)

        if hasattr(self, 'checkBox_2'):
            self.checkBox_2.stateChanged.connect(self.toggle_password_visibility)

        if hasattr(self, 'password_edit_2'):
            self.password_edit_2.textChanged.connect(self.change_password_requirements)

        if hasattr(self, 'password_edit_3'):
            self.password_edit_3.textChanged.connect(self.change_password_requirements)

        # Кнопки

        # Переключение страниц
        # Страница 0 - Логин
        # Страница 1 - Регистрация


        # Кнопка "Register" на первой странице -> идем на стр. 1
        self.register_button.clicked.connect(self.go_to_registration_page)
        self.register_button.setText('Регистрация')


        # Кнопка "Return" на второй странице -> возвращаемся на стр. 0
        self.return_button.clicked.connect(self.go_to_login_page)
        self.return_button.setText('Назад')

        # Кнопка "Login" -> Выполняем проверку
        self.login_button.clicked.connect(self.process_login)
        self.login_button.setText('Войти')

        # Кнопка "Register account" (финальная)
        self.register_button_2.clicked.connect(self.process_registration)
        self.register_button_2.setText('Зарегистрироваться')

    # функции

    def toggle_password_visibility(self):
        """Переключает видимость пароля в зависимости от галочки"""
        if self.checkBox.isChecked():
            # Показываем пароль (Normal режим)
            self.password_edit.setEchoMode(QLineEdit.Normal)
        else:
            # Скрываем пароль (Password режим)
            self.password_edit.setEchoMode(QLineEdit.Password)

        if self.checkBox_2.isChecked():
            self.password_edit_2.setEchoMode(QLineEdit.Normal)
            self.password_edit_3.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit_2.setEchoMode(QLineEdit.Password)
            self.password_edit_3.setEchoMode(QLineEdit.Password)

    def change_password_requirements(self):
        pass1 = self.password_edit_2.text()
        pass2 = self.password_edit_3.text()
        if (pass1 == pass2) and (pass1 != '') and (len(pass1) >= 6):
            self.text_label_4.setText('Пароль соответствует требованиям.')
        else:
            self.text_label_4.setText('Пароль несоответствует требованиям.')

    def go_to_registration_page(self):
        """Переключает на страницу регистрации"""
        self.login_edit_2.setText(None)
        self.password_edit_2.setText(None)
        self.password_edit_3.setText(None)
        self.stackedWidget.setCurrentIndex(1)

    def go_to_login_page(self):
        """Переключает на страницу входа"""
        self.stackedWidget.setCurrentIndex(0)

    def go_to_main_page_today(self):
        self.stackedWidget.setCurrentIndex(2)

    def process_login(self):
        """Логика входа в систему"""
        login = self.login_edit.text()
        password = self.password_edit.text()

        try:
            response = requests.post(settings.URL + '/login', json={'login': login, 'password': password})
            data = response.json()

            if response.status_code == 200:
                QMessageBox.information(self, "Авторизация", data.get('message', 'Успешный вход'))
                self.go_to_main_page_today()
            else:
                try:
                    error_message = data.get('message', 'Неизвестная ошибка')
                except:
                    error_message = data.text if data.text else f'Ошибка {data.status_code}'

                QMessageBox.warning(self, 'Ошибка', error_message)

        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к серверу!")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Произошла ошибка: {str(e)}")



    def process_registration(self):
        """Логика регистрации"""
        new_login = self.login_edit_2.text()
        pass1 = self.password_edit_2.text()
        pass2 = self.password_edit_3.text()

        if '' in [new_login, pass1, pass2]:
            QMessageBox.warning(self, "Ошибка", "Вы заполнили не все поля!")
            return

        if pass1 != pass2:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
            return

        if len(new_login) < 3:
            QMessageBox.warning(self, "Ошибка", "Логин слишком короткий!")
            return

        # Если всё ок
        try:
            response = requests.post(settings.URL + '/register', json={'login': new_login, 'password': pass1})
            data = response.json()

            if response.status_code == 200:
                QMessageBox.information(self, "Регистрация", data.get('message', 'Аккаунт успешно создан!'))
                self.go_to_login_page()
            else:
                try:
                    error_message = data.get('message', 'Неизвестная ошибка')
                except:
                    error_message = data.text if data.text else f'Ошибка {data.status_code}'

                QMessageBox.warning(self, 'Ошибка', error_message)

        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self, "Ошибка", "Нет подключения к серверу!")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Произошла ошибка: {str(e)}")



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec())