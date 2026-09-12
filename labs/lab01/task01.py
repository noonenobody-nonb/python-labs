import random
from enum import Enum
from string import ascii_uppercase, digits, punctuation

passwords = ["InfoS3c@2023", "simple123", "Def3ns3@Key", "public",
             "Encrypt3d#Pass", "basic123", "Secur3@Analysis", "temp123", "Pr0t3ct@Data",
             "default", "Basic123"]
criteria = {"min_length": 8, "require_digits": True, "require_upper": True,
            "require_special": True}
forbidden_passwords = {"simple123", "public", "basic123", "temp123", "default",
                       "guest"}

class Strength(Enum):
    FORBIDDEN = 0
    WEAK = 1
    MEDIUM = 2
    STRONG = 3
    VERY_STRONG = 4

def check_password(password : str, criteria : dict, passwords : list[str] = passwords ) -> Strength:
    if password in forbidden_passwords or len(password) < criteria["min_length"]:
        return Strength.FORBIDDEN

    requirement_count = 0
    requirements_met = 0

    if criteria["require_digits"]:
        requirement_count += 1
        if not set(password).isdisjoint(digits):
            requirements_met += 1

    if criteria["require_upper"]:
        requirement_count += 1
        if not set(password).isdisjoint(ascii_uppercase):
            requirements_met += 1

    if criteria["require_special"]:
        requirement_count += 1
        if not set(password).isdisjoint(punctuation):
            requirements_met += 1

    if requirements_met == requirement_count:
        if (passwords.count(password) <= 1) and (len(password) >= criteria["min_length"] + 4):
            return Strength.VERY_STRONG
        else:
            return Strength.STRONG

    if requirements_met == 1:
        return Strength.WEAK
    elif requirements_met == 2:
        return Strength.MEDIUM

    else:
        return Strength.FORBIDDEN # Не знаю як визначати який це має бути пароль

def check_passwords(passwords: list[str], criteria : dict) -> dict[str, Strength]:
    random_idx = random.sample(range(len(passwords)), 3)
    for idx in random_idx:
        passwords.append(passwords[idx])

    strengths_dict = {}
    for password in passwords:
        strengths_dict[password] = check_password(password, criteria, passwords)

    return strengths_dict

def print_strengths(strengths_dict: dict[str, Strength]):
    print(f"{'Password':<25} | {'Strength':>12}")
    print("-" * 100)
    for password, value in strengths_dict.items():
        value = str(value)[9::]
        print(f"{password:<25} | {value:>12}")

