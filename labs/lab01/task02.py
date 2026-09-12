users = {
"red_team_lead": {"role": "red_team", "clearance": 4, "department": "Red Team", "active": True},
"blue_team_analyst": {"role": "blue_team", "clearance": 3, "department":
"Blue Team", "active": True},
"purple_team_coord": {"role": "purple_team", "clearance": 3, "department":
"Purple Team", "active": True},
"student_intern": {"role": "student", "clearance": 1, "department":
"Academia", "active": True},
"retired_expert": {"role": "retired", "clearance": 2, "department":
"Emeritus", "active": False}
}
resources = [("attack_scenarios", 4), ("defense_playbooks", 3),
("exercise_plans", 3), ("research_papers", 1), ("exploit_tools", 4),
("student_resources", 1), ("simulation_results", 3), ("red_team_tools", 4),
("blue_team_reports", 3), ("public_research", 1)]
security_levels = ("Academic", "Operational", "Tactical", "Strategic")
blocked_users = {"retired_expert", "academic_violator", "leaked_account"}

def print_resources(resources: list, security_levels: tuple):
    for resource in resources:
        print(f"{resource[0]}: {security_levels[resource[1] - 1]}")

def check_user(user: str, users: dict, resources: list, blocked_users: set, resource_name: str) -> str:
    if user not in users:
        return "DENY (User not found)"
    if user in blocked_users:
        return "DENY (User is blocked)"
    if users[user]["active"] == False:
        return "DENY (Account inactive)"
    for resource in resources:
        if resource[0] == resource_name:
            if users[user]["clearance"] >= resource[1]:
                return "ALLOW"
            else:
                return "DENY (Insufficient clearance)"

def print_access(users: dict, resources: list, blocked_users: set):
    for user in users:
        for resource in resources:
            print(f"user = {user}, resource = {resource[0]} -> {check_user(user, users, resources, blocked_users, resource[0])}")
        print("-" * 100)



