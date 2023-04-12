from pykeepass import PyKeePass
import paramiko
import dotenv
import os
from password_generator import PasswordGenerator


dotenv.load_dotenv()
KEYPASS_DATABASE_PATH = os.getenv('KEYPASS_DATABASE_PATH')
KEYPASS_DATABASE_PASSWORD = os.getenv('KEYPASS_DATABASE_PASSWORD')
KEYPASS_ROOT_FOLDER = os.getenv('KEYPASS_ROOT_FOLDER')

pwo = PasswordGenerator()
pwo.minlen = 24
pwo.maxlen = 24
pwo.minuchars = 1
pwo.minlchars = 1
pwo.minnumbers = 1
pwo.minschars = 1
pwo.excludeschars = "'\"\\"  # exclude quotes and backslash


def create_group(parent_group: str, group_name: str):
    """
    Create a new group in the root group
    :param parent_group: name of the root group
    :param group_name: name of the group to create
    :return: None
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    root_group = kp.find_groups(name=parent_group, first=True)
    if root_group is None:
        raise ValueError(f'Group {parent_group} does not exist')
    kp.add_group(root_group, group_name)
    kp.save()


def create_entry(group_name: str, entry_name: str, username: str, password: str, url: str = None):
    """
    Create a new entry in the specified group
    :param group_name: name of the group to create the entry in
    :param entry_name: name of the entry
    :param username: username of the entry
    :param password: password of the entry
    :param url: url of the entry
    :return: None
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    group = kp.find_groups(name=group_name, first=True)
    if group is None:
        raise ValueError(f'Group {group_name} does not exist')
    kp.add_entry(group, entry_name, username, password, url=url)
    kp.save()


def update_entry_password(entry_name: str, new_password: str):
    """
    Update the password of an entry
    :param entry_name: name of the entry
    :param new_password: new password of the entry
    :return: None
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    entry = kp.find_entries(title=entry_name, first=True)
    if entry is None:
        raise ValueError(f'Entry {entry_name} does not exist')
    entry.password = new_password
    kp.save()


def get_groups(category_name: str):
    """
    Get all groups in the root group
    :param category_name: name of the root group
    :return: list of groups
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    root_group = kp.find_groups(name=category_name, first=True)
    if root_group is None:
        raise ValueError(f'Root group {root_group} does not exist')
    return root_group.subgroups


def get_group_entries(group_name: str):
    """
    Get all entries in a group
    :param group_name: name of the group
    :return: list of entries
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    group = kp.find_groups(name=group_name, first=True)
    if group is None:
        raise ValueError(f'Group {group_name} does not exist')
    return group.entries


def find_entry(entry_name: str):
    """
    Find an entry
    :param entry_name: name of the entry
    :return: True if the entry exists, False otherwise
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    if kp.find_entries(title=entry_name, first=True) is None:
        return False
    else:
        return True


def find_group(group_name: str):
    """
    Find a group
    :param group_name: name of the group
    :return: True if the group exists, False otherwise
    """
    kp = PyKeePass(KEYPASS_DATABASE_PATH, password=KEYPASS_DATABASE_PASSWORD)
    if kp.find_groups(name=group_name, first=True) is None:
        return False
    else:
        return True


def ssh_execute_command(server: str, username: str, password: str, command: str):
    """
    Connect to a remote server via SSH
    :param server: IP address of the remote server
    :param username: username of the remote server
    :param password: password of the remote server
    :param command: command to execute
    :return: None
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command(command)
    if stderr:
        print(stderr.read())
    ssh.close()


def change_linux_password(server: str, username: str, password: str, new_password: str):
    """
    Change the password of a Linux user
    :param server: IP address of the remote server
    :param username: username of the remote server
    :param password: password of the remote server
    :param new_password: new password of the remote server
    :return: None
    """
    ssh_execute_command(server, username, password, f"echo '{username}:{new_password}' | chpasswd")


def change_idrac_password(server: str, username: str, password: str, new_password: str):
    """
    Change the password of an iDRAC
    :param server: IP address of the remote server
    :param username: username of the remote server
    :param password: password of the remote server
    :param new_password: new password of the remote server
    :return: None
    """
    ssh_execute_command(server, username, password, f"racadm set iDRAC.Users.2.Password {new_password}")


def main():
    """
    Main function
    :return: None
    """
    root = get_groups(KEYPASS_ROOT_FOLDER)
    for group in root:
        entries = get_group_entries(group.name)
        for entry in entries:
            new_password = pwo.generate()

            if not find_group(f"{group.name}.old"):
                create_group(f"{group.name}", f"{group.name}.old")

            if not find_entry(f"{entry.title} - old"):
                create_entry(f"{group.name}.old", f"{entry.title} - old", entry.username, entry.password, entry.url)
            else:
                update_entry_password(f"{entry.title} - old", entry.password)

            if 'linux' in group.name.lower():
                change_linux_password(entry.url, entry.username, entry.password, new_password)
                # print(f"{entry.title} - {new_password} - {entry.url} - {entry.username} - {entry.password}")
            elif 'idrac' in group.name.lower():
                change_idrac_password(entry.url, entry.username, entry.password, new_password)
                # print(f"{entry.title} - {new_password} - {entry.url} - {entry.username} - {entry.password}")
            update_entry_password(entry.title, new_password)


if __name__ == '__main__':
    main()
