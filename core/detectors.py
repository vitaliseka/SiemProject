from django.utils import timezone
from datetime import timedelta
from core.models import LogEntry, Alert
from django.db.models import Count, Q
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


def create_alert(log_entry, severity, rule_name, description):
    """
    Creates a new Alert object based on a log entry and additional details.

    Args:
        log_entry: The parsed log entry dictionary.
        severity: The severity level of the alert (e.g., "high", "medium", "low").
        rule_name: The name of the rule that triggered the alert.
        description: A human-readable description of the alert.

    Returns:
        The ID of the newly created Alert object.

    This function creates a new Alert object using the Django ORM's `create` method.
    It sets the following fields:
        - log_entry: The parsed log entry dictionary.
        - severity: The severity level of the alert.
        - rule_name: The name of the rule that triggered the alert.
        - description: A human-readable description of the alert.
        - triggered_at: The current timestamp using timezone awareness.

    It then retrieves the ID of the newly created Alert object.

    Finally, the function uses Django Channels to send an alert message
    asynchronously to a group named "alerts". The message includes details
    like description, rule name, severity, and the alert ID.
    """
    alert = Alert.objects.create(
        log_entry=log_entry,
        severity=severity,
        rule_name=rule_name,
        description=description,
        triggered_at=timezone.now(),
    )
    alert_id = alert.id

    # Send alert via Channels
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "alerts",
        {
            "type": "send_alert",
            "message": description,
            "rule_name": rule_name,
            "severity": severity,
            "id": alert_id,
        },
    )


def detect_failed_logins():
    """
    Detects potential brute-force attacks by identifying IP addresses with
    excessive failed login attempts within a specified time window.

    This function performs the following steps:

    1. Defines a time threshold (e.g., 10 days in the past).
    2. Queries for LogEntry objects containing "failed login" within the time window.
    3. Groups entries by IP address and counts the number of attempts for each IP.
    4. Filters for IP addresses with more than a defined threshold of attempts (e.g., 5).

    5. For each high-attempt IP:
        - Creates a human-readable description of the alert.
        - Retrieves all failed login entries for that IP within the time window.
        - For each failed login entry, creates a new Alert object with details:
            - Severity: "HIGH"
            - Rule name: "detect_failed_logins"
            - Description: The generated description about the IP and attempts.
            - Log entry: The specific log entry object.

    6. (Optional) Prints an alert message for each high-attempt IP to the console.

    This function helps identify suspicious login activity and potentially block
    brute-force attacks.
    """
    time_threshold = timezone.now() - timedelta(days=100000)
    failed_logins = (
        LogEntry.objects.filter(
            timestamp__gte=time_threshold, message__icontains="failed login"
        )
        .values("ip_address")
        .annotate(attempts=Count("ip_address"))
        .filter(attempts__gt=5)
    )

    for entry in failed_logins:
        description = f"{entry['ip_address']} has more than 5 failed login attempts in the last 10 minutes"
        log_entries = LogEntry.objects.filter(
            ip_address=entry["ip_address"],
            timestamp__gte=time_threshold,
            message__icontains="failed login",
        )
        for log_entry in log_entries:
            create_alert(log_entry, "HIGH", "detect_failed_logins", description)

    for entry in failed_logins:
        print(
            f"Alert: {entry['ip_address']} has more than 5 failed login attempts in the last 10 minutes"
        )


def detect_high_error_volume():
    """
    Detects a potential surge in error responses by identifying status codes
    greater than or equal to 400 (client errors and server errors) within a time window.

    This function performs the following steps:

    1. Defines a time threshold (e.g., 10 days in the past).
    2. Queries for LogEntry objects with status codes greater than or equal to 400 within the time window.
    3. Groups entries by status code and counts the occurrences for each code.
    4. Filters for status codes with a count exceeding a defined threshold (e.g., 5).

    5. For each high-volume status code:
        - Creates a human-readable description of the alert, mentioning the specific status code.
        - Retrieves all log entries with that status code within the time window.
        - Creates a limited number of Alert objects (e.g., 5 or 6) with details:
            - Severity: "MEDIUM"
            - Rule name: "detect_high_error_volume"
            - Description: The generated description about the status code and volume.
            - Log entry: The specific log entry object.

    6. (Optional) Prints an alert message for each high-volume status code to the console.

    This function helps identify potential issues causing a significant increase in error responses.
    """
    time_threshold = timezone.now() - timedelta(days=100000)
    errors = (
        LogEntry.objects.filter(timestamp__gte=time_threshold, status_code__gte=400)
        .values("status_code")
        .annotate(count=Count("status_code"))
        .filter(count__gt=5)
    )

    for error in errors:
        description = f"High volume of {error['status_code']} errors detected in the last 15 minutes"
        log_entries = LogEntry.objects.filter(
            status_code=error["status_code"], timestamp__gte=time_threshold
        )
        # create only 5/6 alerts here
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "MEDIUM", "detect_high_error_volume", description)

    for error in errors:
        print(
            f"Alert: High volume of {error['status_code']} errors detected in the last 15 minutes"
        )


def detect_suspicious_ip_activity():
    """
    Detects suspicious IP activity by identifying IP addresses with a high number of occurrences.

    This function performs the following steps:

    1. Queries for all IP addresses and their respective occurrence counts.
    2. Filters for IP addresses with a count exceeding a defined threshold (e.g., 5).

    3. For each suspicious IP:
        - Creates a human-readable description of the alert.
        - Retrieves all log entries for that IP.
        - Creates a limited number of Alert objects (e.g., 5 or 6) with details:
            - Severity: "HIGH"
            - Rule name: "detect_suspicious_ip_activity"
            - Description: The generated description about the IP.
            - Log entry: The specific log entry object.

    4. (Optional) Prints an alert message for each suspicious IP to the console.

    This function helps identify potential malicious activity originating from specific IP addresses.
    """

    all_ips = (
        LogEntry.objects.values("ip_address")
        .annotate(count=Count("ip_address"))
        .filter(count__gt=5)  # Adjust threshold as needed
    )
    for entry in all_ips:
        description = f"Suspicious IP activity detected from {entry['ip_address']}"
        log_entries = LogEntry.objects.filter(ip_address=entry["ip_address"])
        # Create a limited number of alerts
        for log_entry in log_entries[:5]:
            create_alert(
                log_entry, "HIGH", "detect_suspicious_ip_activity", description
            )

    # Optional: Print alert messages to console (can be replaced with logging)
    for entry in all_ips:
        print(f"Alert: Suspicious IP activity detected from {entry['ip_address']}")


def detect_sql_injection():
    """
    Detects potential SQL injection attempts by searching for common SQL keywords
    within log messages within a specified time window.

    This function performs the following steps:

    1. Defines a list of common SQL keywords (e.g., SELECT, UNION, DROP, INSERT, UPDATE).
    2. Defines a time threshold (e.g., 10 days in the past).
    3. Queries for LogEntry objects containing any of the defined keywords within the time window.
    4. Uses a regular expression to match the keywords efficiently.

    5. For each potential SQL injection:
        - Creates a human-readable description of the alert, including the suspicious message.
        - Creates a new Alert object with details:
            - Severity: "HIGH"
            - Rule name: "detect_sql_injection"
            - Description: The generated description about the message.
            - Log entry: The specific log entry object.

    6. (Optional) Prints an alert message for each potential SQL injection to the console.

    This function helps identify possible attempts to inject malicious SQL code
    into your application, potentially compromising data integrity or security.

    **Note:** This is a basic example. More sophisticated detection logic might be needed
    depending on the complexity of your application and security requirements.
    """

    sql_keywords = ["SELECT", "UNION", "DROP", "INSERT", "UPDATE"]
    time_threshold = timezone.now() - timedelta(days=100000)  # Adjust time window

    sql_injections = LogEntry.objects.filter(
        timestamp__gte=time_threshold, message__regex="|".join(sql_keywords)
    )

    for entry in sql_injections:
        description = f"Possible SQL injection attempt detected: {entry.message}"
        create_alert(entry, "HIGH", "detect_sql_injection", description)

    for entry in sql_injections:
        print(f"Alert: Possible SQL injection attempt detected: {entry.message}")


def detect_xss_attempts():
    """
    Detects potential Cross-Site Scripting (XSS) attempts by searching for common XSS patterns
    within log messages within a specified time window.

    This function performs the following steps:

    1. Defines a list of common XSS patterns (e.g., `<script>`, `<img`, `<iframe>`).
    2. Defines a time threshold (e.g., 10 days in the past).
    3. Queries for LogEntry objects containing any of the defined patterns within the time window.
    4. Uses a regular expression to match the patterns efficiently.

    5. For each potential XSS attempt (limited to 5 or 6):
        - Creates a human-readable description of the alert, including the suspicious message.
        - Creates a new Alert object with details:
            - Severity: "HIGH"
            - Rule name: "detect_xss_attempts"
            - Description: The generated description about the message.
            - Log entry: The specific log entry object.

    6. (Optional) Prints an alert message for each potential XSS attempt to the console.

    This function helps identify possible attempts to inject malicious scripts
    into your application, potentially compromising user sessions or stealing data.

    """
    xss_patterns = ["<script>", "<img", "<iframe"]
    time_threshold = timezone.now() - timedelta(days=100000)
    xss_attempts = LogEntry.objects.filter(
        timestamp__gte=time_threshold, message__regex="|".join(xss_patterns)
    )

    # Limit the number of alerts created to avoid overwhelming with notifications
    # create only 5/6 alerts here
    for entry in xss_attempts[:5]:
        description = f"Possible XSS attempt detected: {entry.message}"
        create_alert(entry, "HIGH", "detect_xss_attempts", description)

    for entry in xss_attempts:
        print(f"Alert: Possible XSS attempt detected: {entry.message}")


def detect_port_scanning():
    """
    Detects potential port scanning activity by analyzing log entries for
    repetitive connection attempts to different ports within a short time frame.

    This function performs the following steps:

    1. Defines a time threshold (e.g., 10 minutes) for considering connection attempts as part of a potential scan.
    2. Queries for log entries containing network connection information (e.g., source IP, destination port).
    3. Groups log entries by source IP and destination port, counting the number of connections.
    4. Filters for IP addresses with a high number of connections to different ports within the time window.

    5. For each suspicious IP:
        - Creates a human-readable description of the alert, including the IP address and number of connections.
        - Creates a new Alert object with details:
            - Severity: "MEDIUM" (adjust as needed)
            - Rule name: "detect_port_scanning"
            - Description: The generated description about the IP and port scanning activity.
            - Log entry: One of the log entries associated with the suspicious IP (optional).

    6. (Optional) Prints an alert message for each suspicious IP to the console.

    This function helps identify potential port scanning attempts, which could be a precursor to other attacks.
    """

    time_threshold = timezone.now() - timedelta(minutes=10)  # Adjust time window

    # Query for network connection log entries
    connections = LogEntry.objects.filter(timestamp__gte=time_threshold)

    # Group connections by source IP and destination port, counting occurrences
    port_scans = connections.values("ip_address", "destination_port").annotate(
        count=Count("id")
    )

    # Filter for IPs with a high number of connections to different ports
    suspicious_ips = (
        port_scans.filter(count__gt=10).values("ip_address").distinct()
    )  # Adjust threshold

    for ip in suspicious_ips:
        description = (
            f"Suspicious port scanning activity detected from {ip['ip_address']}"
        )
        log_entries = connections.filter(ip_address=ip["ip_address"])
        # Create a limited number of alerts
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "MEDIUM", "detect_port_scanning", description)

    # Optional: Print alert messages to console (can be replaced with logging)
    for ip in suspicious_ips:
        print(
            f"Alert: Suspicious port scanning activity detected from {ip['ip_address']}"
        )


def detect_brute_force():
    time_threshold = timezone.now() - timedelta(days=100000)
    brute_force_attempts = (
        LogEntry.objects.filter(
            timestamp__gte=time_threshold, message__icontains="login attempt"
        )
        .values("ip_address")
        .annotate(count=Count("ip_address"))
        .filter(count__gt=10)
    )

    for attempt in brute_force_attempts:
        description = f"Potential brute force attack from {attempt['ip_address']}"
        log_entries = LogEntry.objects.filter(
            ip_address=attempt["ip_address"],
            timestamp__gte=time_threshold,
            message__icontains="login attempt",
        )
        # create only 5/6 alerts here
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "HIGH", "detect_brute_force", description)

    for attempt in brute_force_attempts:
        print(f"Alert: Potential brute force attack from {attempt['ip_address']}")


def detect_unauthorized_access():
    restricted_paths = ["/admin", "/config", "/etc/passwd"]
    time_threshold = timezone.now() - timedelta(days=100000)
    unauthorized_access = LogEntry.objects.filter(
        timestamp__gte=time_threshold, message__regex="|".join(restricted_paths)
    )

    # create only 5/6 alerts here
    for entry in unauthorized_access[:5]:
        description = f"Unauthorized access attempt detected: {entry.message}"
        create_alert(entry, "HIGH", "detect_unauthorized_access", description)

    for entry in unauthorized_access:
        print(f"Alert: Unauthorized access attempt detected: {entry.message}")


def detect_dos_attacks():
    time_threshold = timezone.now() - timedelta(days=100000)
    high_volume_requests = (
        LogEntry.objects.filter(timestamp__gte=time_threshold)
        .values("ip_address")
        .annotate(request_count=Count("ip_address"))
        .filter(request_count__gt=10)
    )

    for entry in high_volume_requests:
        description = f"Potential DoS attack from {entry['ip_address']} with {entry['request_count']} requests in the last hour"
        log_entries = LogEntry.objects.filter(
            ip_address=entry["ip_address"], timestamp__gte=time_threshold
        )
        # create only 5/6 alerts here
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "CRITICAL", "detect_dos_attacks", description)

    for entry in high_volume_requests:
        print(
            f"Alert: Potential DoS attack from {entry['ip_address']} with {entry['request_count']} requests in the last minute"
        )


def detect_targeted_dos():
    time_threshold = timezone.now() - timedelta(days=100000)
    targeted_dos = (
        LogEntry.objects.filter(timestamp__gte=time_threshold)
        .values("request_details")
        .annotate(request_count=Count("request_details"))
        .filter(request_count__gt=10)
    )

    for entry in targeted_dos:
        description = f"Potential DoS attack targeting {entry['request_details']} with {entry['request_count']} requests in the last hour"
        log_entries = LogEntry.objects.filter(
            request_details=entry["request_details"], timestamp__gte=time_threshold
        )
        # create only 5/6 alerts here
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "CRITICAL", "detect_targeted_dos", description)

    for entry in targeted_dos:
        print(
            f"Alert: Potential DoS attack targeting {entry['request_details']} with {entry['request_count']} requests in the last minute"
        )


def detect_unusual_mail_activity():
    time_threshold = timezone.now() - timedelta(days=100000)
    high_volume_emails = (
        LogEntry.objects.filter(
            timestamp__gte=time_threshold, message__icontains="sendmail"
        )
        .values("message")
        .annotate(email_count=Count("message"))
        .filter(email_count__gt=50)
    )

    for entry in high_volume_emails:
        description = f"Unusual mail activity detected: {entry['message']} with {entry['email_count']} emails sent in the last day"
        log_entries = LogEntry.objects.filter(
            message=entry["message"], timestamp__gte=time_threshold
        )
        # create only 5/6 alerts here
        for log_entry in log_entries[:5]:
            create_alert(log_entry, "HIGH", "detect_unusual_mail_activity", description)

    for entry in high_volume_emails:
        print(
            f"Alert: Unusual mail activity detected: {entry['message']} with {entry['email_count']} emails sent in the last 5 minutes"
        )


def detect_spam_phishing():
    spam_keywords = ["win", "prize", "free", "click here", "urgent"]
    time_threshold = timezone.now() - timedelta(days=100000)
    spam_phishing_emails = LogEntry.objects.filter(
        timestamp__gte=time_threshold, mail_activity__regex="|".join(spam_keywords)
    )

    # create only 5/6 alerts here
    for entry in spam_phishing_emails[:5]:
        description = f"Potential spam/phishing email detected: {entry.mail_activity}"
        create_alert(entry, "HIGH", "detect_spam_phishing", description)

    for entry in spam_phishing_emails:
        print(f"Alert: Potential spam/phishing email detected: {entry.mail_activity}")
