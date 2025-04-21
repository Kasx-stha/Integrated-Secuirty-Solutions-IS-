import os
import time

def write_alert_to_file(alert_message: str, alert_file: str = '/usr/local/etc/snort/ids_alert.txt'):
    """
    Write the alert message to a specified alert file.
    If the file does not exist, it will be created.
    
    :param alert_message: The alert message to be written.
    :param alert_file: The file where the alert will be logged.
    """
    try:
        os.makedirs(os.path.dirname(alert_file), exist_ok=True)
        with open(alert_file, 'a') as f:
            f.write(f"{alert_message} | Time: {time.ctime()}\n")
        print("[DEBUG] Alert successfully written to file.")
    except Exception as e:
        print(f"[ERROR] Failed to write alert to file: {e}")
