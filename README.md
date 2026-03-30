# DNS Server

**Авторитативный DNS-сервер** на C# (.NET), реализующий базовый функционал обработки DNS-запросов.

---

## Установка

### Предварительные требования

- NET.10+

### Использованные библиотеки:

- Log4Net
- YamlDotNet

**Примечание:** *Вероятно, требование к версии .Net преувеличено.*

### Клонирование и сборка

```bash
# Клонируйте репозиторий
git clone https://github.com/Krakenrek/DNSServer.git
cd DNSServer

# Востановите пакеты (зависимости)
dotnet restore

# Соберите проект
dotnet build
```

---

## Конфигурация

Конфигурация производится через YAML-файл `config.yaml`, расположенный в той же директории, что и исполняемый файл.

### Пример

```yaml
zones:
  - domain: example.com
    soa:
      m_name: ns1.example.com
      r_name: admin.example.com
      serial: 2026032801
      refresh: 3600
      retry: 1800
      expire: 604800
      minimum: 3600
    ns_records:
      - ns1.example.com
    a_records:
      - name: ""
        value: 1.2.3.4
        ttl: 3600
      - name: www
        value: 5.6.7.8
        ttl: 3600
    aaaa_records:
      - name: www
        value: 1:2:3:4:5:6:7:8
```

| Поле          | Описание          | Обязательность/количество   |
|---------------|-------------------|-----------------------------|
| `domain`      | Доменное имя зоны | Обязательно, только одно    |
| `soa`         | SOA-запись зоны   | Обязательно, только одно    |
| `nsrecords`   | Список NS-записей | Обязательно, не менее одной |
| `arecords`    | A-записи          | Опционально                 |
| `aaaarecords` | AAAA-записи       | Опционально                 |

**Примечание:** *Присутствует обновление конфигурации без выключения, отправьте сигнал SIGHUP, и программа загрузит
содержимое `config.yaml`.*

---

## Запуск

```bash
# Запустить через dotnet run
dotnet run

# Или собрать, и запускать исполняемый файл
dotnet build 
#Зависит от версии .Net
cd ./bin/Debug/netX
./DNS 
```

**Остановка:** По сигналам SIGINT, SIGTERM.

**Примечание:** *Для успешной работы программе нужен доступ к 53 порту UDP. Используйте sudo.*

---

## Тестирование

### Ручное тестирование

```bash
# Проверка A-записи
dig @127.0.0.1 www.example.com A +noall +answer

# Проверка AAAA-записи
dig @127.0.0.1 www.example.com AAAA +noall +answer

# Проверка NS-записей
dig @127.0.0.1 example.com NS +noall +answer

# Проверка SOA
dig @127.0.0.1 example.com SOA +noall +answer

# Проверка несуществующей записи
dig @127.0.0.1 nonexist.example.com A

# Проверка зоны, за которую сервер не отвечает
dig @127.0.0.1 google.com A

# Проверка рекурсии (должна быть отключена)
dig @127.0.0.1 google.com A +recurse
```

**Примечание:** Автоматических тестов нет.

---

## Примеры запросов

Пока пусто...

---

## Архитектура

### Структура проекта

```
DNSServer/
├── Launch.cs                      # Точка входа программы, запуск сервера
├── DNSServer.cs                   # Непосредственно DNS-сервер
├── Config/
│   ├── DNSConfig.cs               # Представление конфигурации
│   ├── DNSZone.cs                 # Конфигурация DNS-зоны
│   └── Record/
│       ├── AAAARecord.cs          # Конфигурация AAAA записи
│       ├── ARecord.cs             # Конфигурация A записи
│       └── SOARecord.cs           # Конфигурация SOA записи
├── Packet/
│   ├── DnsParseException.cs       # Кастомный тип исключения для парсинга
│   ├── DNSHelper.cs               # Класс вспомогательных функций для работы с пакетами
│   ├── DNSPacketJSONConverter.cs  # Преобразователь DNS-пакетов в JSON
│   ├── DNSResponseBuilder.cs      # Строитель DNS-ответов
│   ├── Enum/
│   │   ├── DNSClass.cs            # Перечисление классов записей
│   │   └── DNSType.cs             # Перечисление типов записей
│   └── Serializable/
│       ├── DNSHeader.cs           # Заголовок DNS-пакета
│       ├── DNSPacket.cs           # DNS-пакет
│       ├── DNSQuestion.cs         # DNS-вопрос
│       ├── DNSResourceRecord.cs   # Ресурная запись
│       └── IDNSSerializable.cs    # Интерфейс бинарной сериализации
└── Storage/
    └── Records.cs                 # Простая реалиация хранилища в памяти

```

---

## Ограничения

- Только авторитативный режим.
- Поддерживаются только A, AAAA, SOA, NS записи.
- Только UDP.
- Нет Dynamic Updates.
- Единый файл конфигурации.
- Нет автоматической элевации привелегий.
