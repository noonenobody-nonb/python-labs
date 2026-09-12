from task01 import passwords, criteria, print_strengths, check_passwords
from task02 import users, resources, security_levels, blocked_users, print_access, print_resources
from task03 import users_to_register, create_users, print_users, login

def main():
    print_strengths(check_passwords(passwords, criteria))
    print_resources(resources, security_levels)
    print_access(users, resources, blocked_users)
    create_users(users_to_register)
    print_users()
    login(username="user10", password="password10")

if __name__ == "__main__":
    main()