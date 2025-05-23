# 🗝️ Password Manager (Milestone 3)

> **⚠️ Архивный проект**  
> Этот проект не завершён и вряд ли когда-либо будет. Он здесь для истории. Всё как есть — баги, костыли, гениальные решения и внезапные "а что если…".

## 📦 Описание

Это был (а может и есть?) мой мини-менеджер паролей на Python. Основная идея — хранить пароли в `.txt`-файлах, шифровать их с помощью `Fernet`, управлять базами и экспериментировать с функционалом мастер-пароля. Тут куча задумок: конфиги, ключи шифрования, SQLite (на будущее), и даже GHOST MODE .

## 🔧 Возможности (реализованные)
- Загрузка/создание конфигурации (`config.json`);
- Поддержка мастер-пароля (bcrypt);
- Генерация и загрузка ключей (`Fernet`);
- Шифрование и дешифровка баз данных;
- Работа с файлами баз (`Password List.json`);
- Обработка настроек вроде общего ключа, запрета на дешифровку, ghost-режима и пр.

## 🛠️ Зависимости

- Python 3.10+  
- `cryptography`  
- `bcrypt`  

Установить зависимости можно через pip:

```bash
pip install cryptography bcrypt
```

## 🚧 Что не доделано
- Отдельное хранилище логинов и email'ов;
- Полная поддержка SQLite;
- Чтение незашифрованных баз;
- Расширенная CLI-интерфейс и/или GUI;
- Поддержка импорта/экспорта;

## 📁 Структура проекта (ожидалась)

```
├── config.json               # Настройки приложения
├── Password List.json       # Список баз
├── *.key                    # Ключи шифрования
├── *.txt                    # Зашифрованные данные
├── master_password.txt      # Хэш мастер-пароля
└── Password manager.py      # Основной код
```

## 📜 Лицензия

💀 _No license, no guarantees, no warranty._  
**Архивный код — пользуйтесь на свой страх и риск.**
