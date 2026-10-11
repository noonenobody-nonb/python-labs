import json
import re
from collections import Counter


def get_password_mask(password: str) -> str:
    mask_chars = []

    for char in password:
        if re.match(r'[A-Z]', char):
            mask_chars.append('?u')
        elif re.match(r'[a-z]', char):
            mask_chars.append('?l')
        elif re.match(r'[0-9]', char):
            mask_chars.append('?d')
        else:
            mask_chars.append('?s')

    return "".join(mask_chars)

def analyze_password(path: str, length: int) -> tuple[list, float, int, str]:
    passwords_mask_list = []
    total_length = 0
    weak_counter = 0
    with open(path, encoding="iso-8859-1", newline='') as f:
        passwords = f.read().splitlines()
        for password in passwords:
            temp_mask = get_password_mask(password)
            passwords_mask_list.append(temp_mask)
            temp_len = len(password)
            total_length += temp_len
            if temp_len < length:
                weak_counter += 1
    avg_length = total_length / len(passwords_mask_list)
    return passwords_mask_list, avg_length, weak_counter, path

def process_data(password_mask_list: list, avg_length: float, weak_counter: int, path: str, top_masks: int, output_path: str) -> None:
    print(f'Processing dictionary file {path}...')
    amount_of_passwords = len(password_mask_list)
    mask_counter = Counter(password_mask_list)
    i = 1
    if amount_of_passwords > 0:
        print(f'Analyzed {amount_of_passwords} password masks.')
    else:
        raise ValueError('No password masks found.')
    print('Summary')
    print(f'{'Total Passwords':<25}: {amount_of_passwords}')
    print(f'{'Weak passwords':<25}: {weak_counter} ({(weak_counter/amount_of_passwords)*100:.1f}%)')
    print(f'{'Average length':<25}: {avg_length:.3f}')
    print()
    data = {}
    data['total_passwords'] = len(password_mask_list)
    data['weak_passwords'] = weak_counter
    data['average_password_length'] = avg_length
    data['top_masks'] = []
    if len(mask_counter) >= top_masks:
        print(f'Top {top_masks} password masks')
        for mask, amount in mask_counter.most_common():
            print(f'{str(i) + '. ' + mask:<30}: {amount} ({(amount/amount_of_passwords)*100:.1f}%)')
            data['top_masks'].append(mask)
            i += 1
            if i > top_masks:
                break
    else:
        raise ValueError('Inputted amount of top masks is incorrect.')

    if output_path is not None:
        with open(output_path, "w", encoding="utf-8", newline='') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
            print()
            print('DATA DUMPED IN JSON FILE')
