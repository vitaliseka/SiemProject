import re
from collections import defaultdict
from datetime import datetime, timedelta


def parse_apache_log(line):
    """
    Parses a line from an Apache error log and extracts relevant information.

    Args:
        line (str): A line from the Apache error log.

    Returns:
        A dictionary containing parsed log information or None if parsing fails.
    """
    pattern = re.compile(
        r"\[(?P<timestamp>[^\]]+)\] \[(?P<log_level>\w+)\] \[client (?P<client_ip>\S+)\] (?P<message>.+)"
    )
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None


def parse_sendmail_log(line):
    """
    Parses a line from a Sendmail log and extracts relevant information.

    Args:
        line (str): A line from the Sendmail log.

    Returns:
        A dictionary containing parsed log information or None if parsing fails.

    This function uses a regular expression to extract details from Sendmail logs
    including timestamp, hostname, process ID, message ID, and details section.
    The details section is further parsed using another regular expression to
    extract key-value pairs.
    """
    # Define a regular expression pattern to match Sendmail log format
    pattern = re.compile(
        r"(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sendmail\[(?P<pid>\d+)\]: (?P<msgid>\S+): (?P<details>.*)"
    )

    # Attempt to match the log line with the pattern
    match = pattern.match(line)

    # If there's a match, extract details
    if match:
        # Convert match object to a dictionary
        log_entry = match.groupdict()

        # Define another regular expression to parse details section
        details_pattern = re.compile(r"(?P<key>\S+)=<*(?P<value>[^,]+)>*")

        # Initialize an empty dictionary to store parsed details
        details = {}

        # Iterate through matches found in the details section using the details_pattern
        for m in details_pattern.finditer(log_entry["details"]):
            # Extract key and value from the match object
            details[m.group("key")] = m.group("value")

        # Add the parsed details dictionary to the log_entry
        log_entry["details"] = details

        # Return the complete parsed log entry dictionary
        return log_entry

    # If no match is found, return None
    return None


def parse_ssl_log(line):
    """
    Parses a line from an SSL/TLS log and extracts relevant information.

    Args:
        line (str): A line from the SSL/TLS log.

    Returns:
        A dictionary containing parsed log information or None if parsing fails.

    This function uses a regular expression to extract timestamp, log level,
    and message from SSL/TLS logs.
    """
    pattern = re.compile(
        r"\[(?P<timestamp>[^\]]+)\] \[(?P<log_level>\w+)\] (?P<message>.+)"
    )
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None


def parse_access_log(line):
    """
    Parses a line from an Apache access log and extracts relevant information.

    Args:
        line (str): A line from the Apache access log.

    Returns:
        A dictionary containing parsed log information or None if parsing fails.

    This function uses a regular expression to extract information about the
    client IP, timestamp, HTTP method, path, protocol, status code, response size,
    referrer, and user agent from an Apache access log line.
    """
    pattern = re.compile(
        r'(?P<client_ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None


def parse_kernel_log(line):
    """
    Parses a line from a kernel log and extracts network traffic information.

    Args:
        line (str): A line from the kernel log.

    Returns:
        A dictionary containing parsed network traffic information or None if parsing fails.

    This function uses a regular expression to extract detailed network traffic
    information from a kernel log line, including timestamp, host, network interfaces,
    IP addresses, protocol, ports, and packet details.
    """
    pattern = re.compile(
        r"(?P<timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) kernel: INBOUND TCP: IN=(?P<in_interface>\S+) PHYSIN=(?P<physin>\S+) OUT=(?P<out_interface>\S+) PHYSOUT=(?P<physout>\S+) SRC=(?P<src_ip>\S+) DST=(?P<dst_ip>\S+) LEN=(?P<len>\d+) TOS=(?P<tos>\S+) PREC=(?P<prec>\S+) TTL=(?P<ttl>\d+) ID=(?P<id>\d+) DF PROTO=(?P<proto>\S+) SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+) WINDOW=(?P<window>\d+) RES=(?P<res>\S+) SYN URGP=(?P<urgp>\d+)"
    )
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None


def parse_timestamp(timestamp_str):
    date_formats = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%d/%m/%y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
    ]
    for date_format in date_formats:
        try:
            timestamp = datetime.strptime(timestamp_str, date_format)
            return timestamp
        except ValueError:
            return f"Error: Unable to parse timestamp from: {timestamp_str}"
