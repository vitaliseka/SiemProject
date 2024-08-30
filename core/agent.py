import os
import requests

# SIEM_SERVER_URL = "http://siem-server.example.com/api/upload_logs/"
SIEM_SERVER_URL = "http://127.0.0.1:8000/upload-api/"
SOURCE_ID = 1


def send_logs_to_siem(log_files_dir):
    """
    Sends log files from a specified directory to a SIEM server.

    This function iterates through files in the given directory, identifies log files
    based on the extension (".log"), and calls the `send_log_file_to_siem` function
    for each eligible file.

    Args:
        log_files_dir (str): Path to the directory containing log files.
    """
    for filename in os.listdir(log_files_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_files_dir, filename)
            send_log_file_to_siem(filepath)


def send_log_file_to_siem(filepath):
    """
    Sends a single log file to the SIEM server.

    This function opens the specified log file in binary mode, prepares data for the
    POST request, and sends it to the SIEM server API endpoint. It handles potential
    exceptions for file access errors and network request failures.

    Args:
        filepath (str): Path to the log file to be sent.
    """
    try:
        with open(filepath, "rb") as f:
            files = {"file": f}
            data = {"source_id": SOURCE_ID}
            response = requests.post(SIEM_SERVER_URL, data=data, files=files)
            if response.status_code == 200:
                print(f"Log file '{filepath}' sent successfully")
            else:
                print(f"Failed to send log file '{filepath}'")
    except IOError as e:
        print(f"Error opening log file '{filepath}': {e}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending log file '{filepath}': {e}")


if __name__ == "__main__":
    """
    Main execution block.

    This block defines the directory containing log files and calls the
    `send_logs_to_siem` function to initiate the log sending process.
    """
    log_files_directory = "logs/"
    send_logs_to_siem(log_files_directory)
