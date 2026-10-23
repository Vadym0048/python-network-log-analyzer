from datetime import datetime


def analyze_log():
    correct_count = 0
    incorrect_count = 0
    success_count = 0
    failed_count = 0

    failed_by_ip = {}
    port_counts = {}

    try:
        with open("network_log.txt", "r", encoding="utf-8") as file:
            for line in file:
                fields = line.strip().split(";")

                # Перевірка кількості полів
                if len(fields) != 4:
                    incorrect_count += 1
                    continue

                ip = fields[1]
                status = fields[2]
                port = fields[3]

                # Перевірка статусу
                if status != "SUCCESS" and status != "FAILED":
                    incorrect_count += 1
                    continue

                # Перетворення порту на число
                try:
                    port = int(port)
                except ValueError:
                    incorrect_count += 1
                    continue

                # Перевірка діапазону порту
                if port < 1 or port > 65535:
                    incorrect_count += 1
                    continue

                # Статистика лише коректних записів
                correct_count += 1

                if status == "SUCCESS":
                    success_count += 1
                else:
                    failed_count += 1

                    if ip in failed_by_ip:
                        failed_by_ip[ip] += 1
                    else:
                        failed_by_ip[ip] = 1

                if port in port_counts:
                    port_counts[port] += 1
                else:
                    port_counts[port] = 1

    except FileNotFoundError:
        print("Файл network_log.txt не знайдено.")
        return None
    except UnicodeError:
        print("Не вдалося прочитати файл. Збережіть його в UTF-8.")
        return None
    except OSError:
        print("Не вдалося відкрити або прочитати журнал.")
        return None

    # Відсоток невдалих підключень
    if correct_count > 0:
        failed_percent = failed_count / correct_count * 100
    else:
        failed_percent = 0

    # IP із найбільшою кількістю невдалих спроб
    top_ip = None
    max_failed = 0

    for address in failed_by_ip:
        if failed_by_ip[address] > max_failed:
            max_failed = failed_by_ip[address]
            top_ip = address

    # Найпопулярніший порт
    top_port = None
    max_port_count = 0

    for port_number in port_counts:
        if port_counts[port_number] > max_port_count:
            max_port_count = port_counts[port_number]
            top_port = port_number

    # Усі підозрілі IP-адреси
    suspicious_ips = {}

    for address in failed_by_ip:
        if failed_by_ip[address] >= 3:
            suspicious_ips[address] = failed_by_ip[address]

    # Повертаємо результати в одному словнику
    return {
        "correct_count": correct_count,
        "incorrect_count": incorrect_count,
        "success_count": success_count,
        "failed_count": failed_count,
        "failed_percent": failed_percent,
        "top_ip": top_ip,
        "max_failed": max_failed,
        "top_port": top_port,
        "max_port_count": max_port_count,
        "suspicious_ips": suspicious_ips,
    }


def show_statistics(results):
    print("\n===== СТАТИСТИКА =====")
    print("Коректних записів:", results["correct_count"])
    print("Некоректних записів:", results["incorrect_count"])
    print("Успішних підключень (SUCCESS):", results["success_count"])
    print("Невдалих підключень (FAILED):", results["failed_count"])
    print(
        f"Відсоток невдалих підключень: "
        f"{results['failed_percent']:.2f}%"
    )

    if results["top_ip"] is None:
        print("Невдалих підключень немає.")
    else:
        print(
            "IP із найбільшою кількістю невдалих спроб:",
            results["top_ip"], "—", results["max_failed"]
        )

    if results["top_port"] is None:
        print("Найпопулярніший порт: немає даних.")
    else:
        print(
            "Найпопулярніший порт:",
            results["top_port"], "—", results["max_port_count"]
        )


def show_suspicious_ips(results):
    print("\n===== ПІДОЗРІЛІ IP-АДРЕСИ =====")
    suspicious_ips = results["suspicious_ips"]

    if suspicious_ips:
        for address in suspicious_ips:
            print(
                address, "—", suspicious_ips[address],
                "невдалих спроб"
            )
    else:
        print("Підозрілих IP-адрес не виявлено.")


def save_report(results):
    try:
        with open("report.txt", "w", encoding="utf-8") as report:
            report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            report.write("ЗВІТ ПРО АНАЛІЗ МЕРЕЖЕВОГО ЖУРНАЛУ\n")
            report.write(f"Дата та час: {report_time}\n\n")

            report.write(
                f"Коректних записів: {results['correct_count']}\n"
            )
            report.write(
                f"Некоректних записів: {results['incorrect_count']}\n"
            )
            report.write(
                f"Успішних підключень (SUCCESS): "
                f"{results['success_count']}\n"
            )
            report.write(
                f"Невдалих підключень (FAILED): "
                f"{results['failed_count']}\n"
            )
            report.write(
                f"Відсоток невдалих підключень: "
                f"{results['failed_percent']:.2f}%\n"
            )

            if results["top_ip"] is None:
                report.write("Невдалих підключень немає.\n")
            else:
                report.write(
                    f"IP із найбільшою кількістю невдалих спроб: "
                    f"{results['top_ip']} — {results['max_failed']}\n"
                )

            if results["top_port"] is None:
                report.write("Найпопулярніший порт: немає даних.\n")
            else:
                report.write(
                    f"Найпопулярніший порт: {results['top_port']} "
                    f"— {results['max_port_count']}\n"
                )

            report.write("\nПідозрілі IP-адреси:\n")
            suspicious_ips = results["suspicious_ips"]

            if suspicious_ips:
                for address in suspicious_ips:
                    report.write(
                        f"{address} — {suspicious_ips[address]} "
                        f"невдалих спроб\n"
                    )
            else:
                report.write("Підозрілих IP-адрес не виявлено.\n")

        print("Звіт збережено у report.txt.")

    except OSError:
        print("Не вдалося записати звіт у report.txt.")


# Основна програма
results = None

while True:
    print("\n===== АНАЛІЗАТОР МЕРЕЖЕВИХ ЖУРНАЛІВ =====")
    print("1. Проаналізувати журнал")
    print("2. Показати статистику")
    print("3. Показати підозрілі IP-адреси")
    print("4. Зберегти звіт")
    print("0. Вихід")

    try:
        choice = input("Ваш вибір: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nРоботу завершено.")
        break

    if choice == "0":
        print("Роботу завершено.")
        break

    elif choice == "1":
        results = analyze_log()

        if results is not None:
            print("Аналіз завершено.")
            print("Коректних записів:", results["correct_count"])
            print("Некоректних записів:", results["incorrect_count"])

    elif choice == "2":
        if results is None:
            print("Спочатку проаналізуйте журнал — пункт 1.")
        else:
            show_statistics(results)

    elif choice == "3":
        if results is None:
            print("Спочатку проаналізуйте журнал — пункт 1.")
        else:
            show_suspicious_ips(results)

    elif choice == "4":
        if results is None:
            print("Спочатку проаналізуйте журнал — пункт 1.")
        else:
            save_report(results)

    else:
        print("Невірний вибір. Введіть 0, 1, 2, 3 або 4.")