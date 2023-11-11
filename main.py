import itertools
import hashlib
import time
import os

from concurrent.futures import ThreadPoolExecutor

def sha256_hash(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def brute_force_passwords(hash_values, num_threads=1):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    password_length = 5
    passwords_to_try = itertools.product(alphabet, repeat=password_length)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for password in passwords_to_try:
            start_time = time.time()
            executor.submit(try_password, password, hash_values)

def try_password(password, hash_values):
    hashed_password = sha256_hash(''.join(password))
    if hashed_password in hash_values:
        end_time = time.time()
        print(f"Пароль найден: {''.join(password)} для хэша: {hashed_password}")
        print(f"Затраченное время: {end_time - start_time} секунд")

if __name__ == "__main__":
    hash_values = [
        "1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
        "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
        "74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f"
    ]

    max_threads = os.cpu_count()
    print(f"Максимальное количество доступных потоков: {max_threads}")
    num_threads = int(input("Введите количество потоков (1 для однопоточных): "))

    start_time = time.time()
    brute_force_passwords(hash_values, num_threads)
    end_time = time.time()

    print(f"Затраченное время, всего: {end_time - start_time} секунд")
