import hashlib
import os
import csv
import functools
import json
from datetime import datetime

min_length = 9
personal_salt = "00006"
folder_name = "data"
users_to_register = [("user1", "password1"), ("user2", "password2"), ("user3", "password3"),
                     ("user4", "password4"), ("user5", "password5"), ("user6", "password6"),
                     ("user7", "password7"), ("user8", "password8"), ("user9", "password9"),
                     ("user10", "password10")]

class ValidationError(Exception):
    def __init__(self, min_length):
        self.min_length = min_length
        super().__init__(f"Minimal length of password characters is {min_length} characters!")

def log_event(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") or (args[0] if len(args) > 0 else None)

        status = False
        error_msg = None

        try:
            status = func(*args, **kwargs)
            return status
        except Exception as e:
            print(e)
            return
        finally:
            log_dir = folder_name
            os.makedirs(log_dir, exist_ok=True)
            log_file_path = os.path.join(log_dir, "logs.json")

            logs = []
            if os.path.exists(log_file_path):
                try:
                    with open(log_file_path, "r+", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, ValueError):
                    logs = []

            log_entry = {
                "event": "login",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "username": username,
                "success": status,
                "args": args,
                "kwargs": kwargs,
            }
            if error_msg:
                log_entry["error"] = error_msg

            logs.append(log_entry)

            with open(log_file_path, "w+", encoding="utf-8") as f:
                json.dump(logs, f, indent=4)

    return wrapper

def generate_hash(password: str, salt: str = "00000") -> str:
    try:
        if salt == "":
            raise ValueError("Salt cannot be empty")
        if len(password) < min_length:
            raise ValidationError(min_length)
        return hashlib.blake2s(f"{password + salt}".encode()).hexdigest()
    except ValueError as e:
        print(e)
        return ""
    except ValidationError as e:
        print(e)
        return ""

def create_user(username: str, password: str) -> tuple:
    try:
        if username == "" or password == "":
            raise ValueError("Username or password cannot be empty!")
        hashed_pwd = generate_hash(password, personal_salt)
        return username, hashed_pwd
    except ValueError as e:
        print(e)
        return ()

def create_users(users_list: list[tuple]) -> None:
    try:
        for user in users_list:
            if users_list.count(user) > 1:
                raise ValueError("Initial list of users must contain only one user!")
            if user == "":
                raise ValueError("Username cannot be empty!")

        if not os.path.exists(folder_name):
            os.mkdir(folder_name)

        users = []
        for user in users_list:
            try:
                if user == "":
                    raise ValueError("Username cannot be empty!")
                users.append(create_user(user[0], user[1]))
            except ValueError as e:
                print(e)
                continue

        with open(os.path.join(folder_name, "users.csv"), "w+", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerows(users)
    except ValueError as e:
        print(e)
        return

def print_users() -> None:
    print(f"{"Username":<25} | {"Password hash":^64}")
    print("-" * 92)
    with open(os.path.join(folder_name, "users.csv"), "r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            try:
                print(f"{row[0]:<25} | {row[1]:^64}")
            except IndexError as e:
                print(e)
                continue
@log_event
def login(username: str, password: str) -> bool:
    try:
        if username == "" or password == "":
            raise ValueError("Username and password cannot be empty!")

        with open(os.path.join(folder_name, "users.csv"), "r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            if not any(username in item for item in reader):
                return False

            file.seek(0)
            hashed_pwd = generate_hash(password, personal_salt)
            for user in reader:
                if username == user[0] and hashed_pwd == user[1]:
                    return True

            return False
    except ValueError as e:
        print(e)
        return False


