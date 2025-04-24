import json
import os
import sys
from cryptography.fernet import Fernet
import typing
import bcrypt
import sqlite3

class config_DATA:
   CONFIG_FILE = "config.json"
   CONFIG = {}

   @staticmethod
   def load_config() -> dict:
       """
       Загружает конфигурацию из файла.
       Если файл не найден или содержит некорректные данные, возвращает пустой словарь.
       """
       try:
           with open("config.json", "r") as json_file:
               config_DATA.CONFIG = json.load(json_file)
               return config_DATA.CONFIG
       except FileNotFoundError:
           print("Файл не найден")
       except json.JSONDecodeError:
           print("Ошибки загрузки")
       return {}

   @staticmethod
   def create_settings(force=False, CONFIG_FILE=None):
       """
       Создает файл конфигурации, если он не существует или если force=True.
       """
       if os.path.exists(config_DATA.CONFIG_FILE) and not force:
           return
       config_DATA.CONFIG = {"LOAD_KEY": True,
                             "CREATE_KEY": True,
                             "SAVE_NOT_CRYPTING": False,
                             "TEST_MODE_QT": False,
                             "REDACTED_DBS": True,
                             "MASTER_PASSWORD": False,
                             "ONE_PASSWORD_KEY_FOR_EVERYONE": False,
                             "GHOST_MODE": True
                             }
       with open(CONFIG_FILE, 'w', encoding="utf-8") as json_file:
           json.dump(config_DATA.CONFIG, json_file, indent=4, ensure_ascii=False)
       return None

class  Manage_Master_Password:
    def Create_Master_Password(self):
        config = config_DATA.load_config()
        master_password = config.get("MASTER_PASSWORD")
        if master_password:
            password = input("Введите пароль: ")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            with open("master_password.txt", "wb") as file:
                file.write(hashed_password)
        else:
            print("Создание пароля запрещено")
            return None
    def Checking_Master_Password(self):
            password = input("Введите пароль: ")
            with open("master_password.txt", "rb") as file:
                hashed_password = file.read()
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    print("Пароль верный")
                    return True
            else:
                    print("Пароль не верный")
                    return False
        

class encrypt_db(config_DATA):

   def __init__(self, name_db, name_db_folder):
       self.name_db = name_db
       self.name_db_folder = name_db_folder

   @property
   def create_key(self):
       """
       Создает ключ шифрования и сохраняет его в файл.
       """
       config = config_DATA.load_config()
       one_passwdord = config.get("ONE_PASSWORD_KEY_FOR_EVERYONE",)
       create_key = config.get("CREATE_KEY")
       key = Fernet.generate_key()
       if create_key:
            if one_passwdord:
               with open("key.key", "wb") as key_file:
                   key_file.write(key)
                   print("Ключ успешно создан и сохранен в", "key.key")
                   return key
            else:
                   with open(self.name_db + ".key", "wb") as key_file:
                       key_file.write(key)
                   print("Ключ успешно создан и сохранен в", self.name_db + ".key")
                   return key

       else:
           print("Создание ключей запрещено")

   @property
   def load_key(self):
       """
       Загружает ключ шифрования из файла.
       """
       config = config_DATA.load_config()
       one_passwdord = config.get("ONE_PASSWORD_KEY_FOR_EVERYONE")
       load_key = config.get("LOAD_KEY")
       if load_key:
           if not one_passwdord:
               try:
                   with open(self.name_db + ".key", "rb") as key_file:
                       return key_file.read()
               except FileNotFoundError:
                   print("Файл не найден")
               return None
           else:
               try:
                   with open("key.key", "rb") as key_file:
                       return key_file.read()
               except FileNotFoundError:
                   print("Файл не найден")
               return None
       else:
           print("Загрузка ключа запрещена")

   def decrypt_db(self):
       """
       Расшифровывает базу данных.
       """
       master = Manage_Master_Password()
       master.Checking_Master_Password()
       if not master.Checking_Master_Password():
        print("Не в этот раз!")
        return None
       key = self.load_key
       if not key:
           print("Сначало создай ключ!")
       fernet = Fernet(key)
       file_path = os.path.join(self.name_db_folder, self.name_db + ".txt")
       with open(file_path, "rb") as file:
           file_data = file.read()
       encrypted_data = file_data
       decrypted_data = fernet.decrypt(encrypted_data).decode()

       # Преобразование из строки JSON в словарь
       decoded_data = json.loads(decrypted_data)

       print("Расшифрованные данные:", decoded_data)
       return decoded_data  # Возвращаем результат, если требуется


class ManageDb(encrypt_db, config_DATA):

   ram_passwords = {}

   def __init__(self, name_db, name_db_folder, ):
       self.name_db = name_db
       self.name_db_folder = name_db_folder
       self.ram_passwords = {}

   @staticmethod
   def load_config_db() -> dict:
       """
       Загружает конфигурацию базы данных из файла.
       Если файл не найден или содержит некорректные данные, возвращает пустой словарь.
       """
       if not os.path.exists("Password List.json"):
           print("Файл не найден")
           return {}

       try:
           with open("Password List.json", "r") as json_file:
               config_data = json.load(json_file)
               if not isinstance(config_data, dict):
                   print("Ошибки загрузки: файл содержит некорректные данные")
                   return {}
               return config_data
       except json.JSONDecodeError:
           print("Ошибки загрузки: файл содержит некорректные данные")
           return {}

   @staticmethod
   def create_db_list(force=False):
       """
       Создает файл конфигурации базы данных, если он не существует.
       """
       with open("Password List.json", 'w', encoding="utf-8") as json_file:
           json.dump({}, json_file, indent=4)
           return {}

   def create_db(self, force=False):
       """
       Создает базу данных и сохраняет ее в файл.
       """
       if not os.path.exists(self.name_db_folder):
           os.mkdir(self.name_db_folder)
       file_path = os.path.join(self.name_db_folder, self.name_db + ".db")
       Base_Data = sqlite3.connect(file_path)
       cur = Base_Data.cursor()  # Создаем объект для работы с базой данных
       cur.execute("CREATE TABLE IF NOT EXISTS passwords (site , password , mail , login , id )")
       while True:
               input_site = input("Назовите имя сайта: ")
               input_password = input("Введите пароль: ")
               while True:
                   if input_password == '':
                       print("Нужно обязательно ввести пар оль!")
                       input_password = input("Введите пароль: ")
                   else:
                       break
               input_mail = input("Введите свою электронную почту(Если вы не хотите ее вводить, то нажмите enter): ")
               input_login = input("Введите логин(Если вы не хотите ее вводить, то нажмите enter): ")
               input_id = int(input("Введите идентификатор: "))
               cur.execute("INSERT INTO passwords (site, password, mail, login, id) VALUES (?, ?, ?, ?, ?)", (input_site, input_password, input_mail, input_login, input_id))
               Base_Data.commit()  # Отправляем данные в базу
               continue_cycle = input("Продолжить добавлять пароли? (да/нет): ")
               if continue_cycle.lower() == 'да':
                   continue
               elif continue_cycle.lower() == 'нет':
                    break
                    # Если база уже существует и force == False, пропускаем обновление
                    if self.name_db in file_path_to_passwords and not force:
                            print(f"База с именем '{self.name_db}' уже существует. Перезапись отключена (force=False).")
                    else:
                            # Добавляем или обновляем текущую запись
                            file_path_to_passwords[self.name_db] = self.name_db_folder
                            # Записываем обновленные данные обратно в JSON-файл с отступами (каждая запись с новой строки)
                            with open(json_file_path, "w") as json_file:
                                json.dump(file_path_to_passwords, json_file, indent=4, ensure_ascii=False)
                            break
                   #print(ManageDb.ram_passwords)
                   #key = self.load_key
                   #if not key:
                       #print("Ключ не найден")
                       #key = self.create_key
                   #fernet = Fernet(key)
                   #data_str = json.dumps(ManageDb.ram_passwords)
                  #data_bytes = data_str.encode()
                   #encrypted_data = fernet.encrypt(data_bytes)
                   #encrypted_data_str = encrypted_data.decode()
                   #file.write(encrypted_data_str)

                   #json_file_path = "Password List.json"
                   ##file_path_to_passwords = {}

                   # Загружаем существующие данные, если JSON-файл существует
                   #try:
                       #with open(json_file_path, "r") as json_file:
                           #file_path_to_passwords = json.load(json_file)
                   #except FileNotFoundError:
                       #pass  # Если файл не существует, начинаем с чистого листа

                   # Если база уже существует и force == False, пропускаем обновление
                   #if self.name_db in file_path_to_passwords and not force:
                       #print(f"База с именем '{self.name_db}' уже существует. Перезапись отключена (force=False).")
                   #else:
                       # Добавляем или обновляем текущую запись
                       #file_path_to_passwords[self.name_db] = self.name_db_folder
                       # Записываем обновленные данные обратно в JSON-файл с отступами (каждая запись с новой строки)
                       #with open(json_file_path, "w") as json_file:
                           #json.dump(file_path_to_passwords, json_file, indent=4, ensure_ascii=False)
                   #break
class List_Db(ManageDb):
   def __init__(self, name_db, name_db_folder):
    self.name_db = name_db
    self.name_db_folder = name_db_folder

   @staticmethod

   def List_all_dbs():
       """
       Выводит список всех баз данных.
       """
       config = ManageDb.load_config_db()
       if config is not None:
           for key, value in config.items():
                print(f"База данных: Название базы паролей '{key}' - Где хранятся шифрованные данные: '{value}'")
   def redacted_db(self):
       file_path = os.path.join(self.name_db_folder, self.name_db + ".db")
       Base_Data = sqlite3.connect(file_path)
       cur = Base_Data.cursor()
       while True:
            print("1: Добавить новые данные в базу")
            print("2: Редактирование базы данных")
            input_number = int(input("Выберите пункт в меню: "))
            if input_number == 1:
                while True:
                    input_site = input("Назовите имя сайта: ")
                    input_password = input("Введите пароль: ")
                    while True:
                        if input_password == '':
                            print("Нужно обязательно ввести пароль!")
                            input_password = input("Введите пароль: ")
                            continue
                        else:
                            break
                    input_mail = input("Введите свою электронную почту(Если вы не хотите ее вводить, то нажмите enter): ")
                    input_login = input("Введите логин(Если вы не хотите ее вводить, то нажмите enter): ")
                    cur.execute("INSERT INTO passwords (site, password, mail, login) VALUES (?, ?, ?, ?)", (input_site, input_password, input_mail, input_login))
                    Base_Data.commit()
                    continue_cycle = input("Продолжить добавлять пароли? (да/нет): ")
                    if continue_cycle.lower() == 'да':
                        continue
                    elif continue_cycle.lower() == 'нет':
                        break
            elif input_number == 2:
                 file_path = os.path.join(self.name_db_folder, self.name_db + ".db")
                 Base_Data = sqlite3.connect(file_path)
                 cur = Base_Data.cursor()  # Создаем объект для работы с базой данных
                 while True:
                    input_id = input("Введите id строки, которую нужно обновить: ")
                    input_new_password = input("Введите новый пароль: ")
                    input_new_site = input("Введите новое имя сайта: ")
                    input_new_login = input("Введите новый логин: ")
                    input_new_mail = input("Введите новый email: ")
                    cur.execute("UPDATE passwords SET password = ?, site = ?, login = ?, mail = ? WHERE id = ?", (input_new_password, input_new_site, input_new_login, input_new_mail, input_id))
                    Base_Data.commit()
                    continue_cycle = input("Продолжить обновлять данные? (да/нет): ")
                    if continue_cycle.lower() != 'да':
                        break

           
class Manage_Settings(config_DATA):
   """
   Класс для управления настройками приложения.
   """
   def settings_Menu(self):
       """
       Метод для отображения меню настроек и обработки выбора пользователя.
       """
       while True:
            print("1: Создание ключей")
            print("2: Загрузка ключей")
            print("3: Ключ для всех баз")
            print("4: Сохранение без шифрование")
            print("5: Тестовый GUI режим")
            print("6: Выход")
            try: 
               input_number = int(input("Выберите пункт меню: "))
            except ValueError:
               print("Пиши число")
               continue
            if input_number == 1:
               input_True_or_False = input("Создать ключи? (да/нет): ")
               if input_True_or_False.lower() == 'да':
                   config = config_DATA.load_config()
                   config['CREATE_KEY'] = True
                   with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                       json.dump(config, json_file, indent=4, ensure_ascii=False)
                   continue
               else:
                   config = config_DATA.load_config()
                   config['CREATE_KEY'] = False
                   with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                       json.dump(config, json_file, indent=4, ensure_ascii=False)
            elif input_number == 2:
                input_True_or_False = input("Загрузить ключи? (да/нет): ")
                if input_True_or_False.lower() == 'да':
                            config = config_DATA.load_config()
                            config['LOAD_KEY'] = True
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
                else:
                            config = config_DATA.load_config()
                            config['LOAD_KEY'] = False
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
            elif input_number == 3:
                input_True_or_False = input("Ключ для всех баз? (да/нет): ")
                if input_True_or_False.lower() == 'да':
                            config = config_DATA.load_config()
                            config['ONE_PASSWORD_KEY_FOR_EVERYONE'] = True
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
                else:
                            config = config_DATA.load_config()
                            config['ONE_PASSWORD_KEY_FOR_EVERYONE'] = False
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
            elif input_number == 4:
                input_True_or_False = input("Сохранение без шифрование? (да/нет): ")
                if input_True_or_False.lower() == 'да':
                            config = config_DATA.load_config()
                            config['SAVE_NOT_CRYPTING'] = True
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
                else:
                            config = config_DATA.load_config()
                            config['SAVE_NOT_CRYPTING'] = False
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
            elif input_number == 5:
                input_True_or_False = input("Тестовый GUI режим? (да/нет): ")
                if input_True_or_False.lower() == 'да':
                            config = config_DATA.load_config()
                            config['TEST_MODE_QT'] = True
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
                else:
                            config = config_DATA.load_config()
                            config['TEST_MODE_QT'] = False
                            with open(config_DATA.CONFIG_FILE, 'w', encoding="utf-8") as json_file:
                               json.dump(config, json_file, indent=4, ensure_ascii=False)
                            continue
            elif input_number == 6:
               break
            else:
               print("Пиши число!")
               continue

class Menu:
   """
   Класс для отображения главного меню приложения и обработки выбора пользователя.
   """
   config = config_DATA.load_config()
   if config is None:
       config_DATA.create_settings(CONFIG_FILE=config_DATA.CONFIG_FILE)
       config = config_DATA.load_config()
   config_db = ManageDb.load_config_db()
   if config_db is None or config_db == {}:
       config_db = ManageDb.create_db_list()
       config_db = ManageDb.load_config_db()
       
   while True:
        print("1: Создание базы паролей")
        print("2: Расшифорвка базы паролей")
        print("3: Выход")
        print("4: О программе")
        print("5: Настройки")
        print("6: Список баз паролей")
        print("7: Создание мастер-пароля")
        print("8: редактирование баз паролей")
        try:
           input_number = int(input("Выберите пунк из меню: "))
        except ValueError:
           print("Пиши число!")
           continue
        if input_number == 1:
           input_name_db = input("Введите название вашей базы: ")
           input_name_db_folder = input("Напиши название, где будут хранится база паролей: ")
           manager = ManageDb(input_name_db, input_name_db_folder)
           manager.create_db()
           continue
        elif input_number == 2:
           input_name_db = input("Введите название вашей базы: ")
           input_name_db_folder = input("Напиши название базы паролей: ")
           manager = ManageDb(input_name_db, input_name_db_folder)
           manager.decrypt_db()
           continue
        elif input_number == 3:
           sys.exit()
        elif input_number == 4:
           print("Password manager версия 0.3.10 ALPHA 3 (Milestone 3)")
        elif input_number == 5:
           settings = Manage_Settings()
           settings.settings_Menu()
           continue
        elif input_number == 6:
           settings = List_Db()
           settings.List_all_dbs()
           continue
        elif input_number == 7:
           settings = Manage_Master_Password()
           settings.Create_Master_Password()
           continue
        elif input_number == 8:
           input_name_db = input("Введите название вашей базы: ")
           input_name_db_folder = input("Напиши название, где будут хранится база паролей: ")
           settings = List_Db(input_name_db, input_name_db_folder)
           settings.redacted_db()

        else:
           print("Пиши число!")
           continue



