from task01 import check_passwords, criteria, passwords, print_strengths
from task02 import (
    blocked_users,
    print_access,
    print_resources,
    resources,
    security_levels,
    users,
)
from task03 import create_users, login, print_users, users_to_register


def main():
    print_strengths(check_passwords(passwords, criteria))
    print_resources(resources, security_levels)
    print_access(users, resources, blocked_users)
    create_users(users_to_register)
    print_users()
    login(username="user10", password="password10")

if __name__ == "__main__":
    main()