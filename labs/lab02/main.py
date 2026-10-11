import argparse
import sys

from task01 import Admin, AuditLog, UserAccount
from task02 import analyze_password, process_data


def demo():
    print("=== DEMO TASK 1 ===")

    audit_log = AuditLog()
    admin_user = Admin(
        username="administrators",
        email="goodjob@gmail.com",
        role="administrator",
        active=True,
        permissions=["READ_LOGS", "MANAGE_USERS"]
    )
    admin_user.set_password("D0g0v0rnya4ok!")

    account = UserAccount(user=admin_user, audit_log=audit_log)
    print(f"New account instance created: {account['user']}")
    print(f"Administration rights: {admin_user}")

    print("\n--- Email validation test ---")
    try:
        account["email"] = "badjob@gmail.com"
        print(f"Email updated successfully: {account['email']}")
    except ValueError as e:
        print(f"Validation error: {e}")

    try:
        print("Trying to set up an invalid email...")
        account["email"] = "fignyaemail"
    except ValueError as e:
        print(f"Expected error intercepted: {e}")

    print("\n--- Authentication test ---")
    account.login("NeToyParol", "192.168.1.50")  # Невдалий вхід
    account.login("D0g0v0rnya4ok!", "192.168.1.50")  # Успішний вхід

    print(f"Is user authenticated? {account.is_authenticated()}")

    print("\n--- Session end---")
    account.logout()
    print(f"Is user authenticated after logout? {account.is_authenticated()}")
    audit_log.show_all()

def analyze():
    parser = argparse.ArgumentParser(
        prog='PSAM',
        description='Nothing to see here.',
        epilog='Really nothing to see here. (i love arch)')

    parser.add_argument('-w', '--wordlist')
    parser.add_argument('-l', '--min-length')
    parser.add_argument('-tm', '--top-masks')
    parser.add_argument('-os', '--output-stats')

    args = parser.parse_args()
    wordlist_path = args.wordlist
    min_length = int(args.min_length)
    top_masks = int(args.top_masks)
    output_stats = args.output_stats
    masks_list, avg_length, weak_passwords, path = analyze_password(wordlist_path, min_length)
    process_data(masks_list, avg_length, weak_passwords, path, top_masks, output_stats)

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "demo":
            demo()
        else:
            analyze()
    except TypeError:
        print('Введіть коректні аргументи')