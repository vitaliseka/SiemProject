from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class LogSource(models.Model):
    """
    Represents a source of log data (e.g., application, server).

    Args:
        name (str): Unique name of the log source.
        description (str): Optional description of the log source.
        hostname (str): Optional hostname associated with the log source.
        ip_address (GenericIPAddressField): Optional IP address of the log source.
        protocol (str): Optional protocol used by the log source (e.g., TCP, UDP).
        log_format (str): Optional field to specify the expected format of logs from this source.
        added_by (ForeignKey): Optional user who added the log source (related to User model).

    """

    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    protocol = models.CharField(max_length=255, blank=True)
    log_format = models.TextField(blank=True)  # Optional: Specify expected log format
    added_by = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.name


class LogFile(models.Model):
    """
    Represents an uploaded log file.

    Args:
        source (ForeignKey): Foreign key referencing the LogSource model.
        file_name (str): Name of the uploaded log file.
        file (FileField): File field storing the actual log file data.
        upload_date (DateTimeField): Date and time of the log file upload (auto-populated).
        file_size (BigIntegerField): Optional field to store the size of the log file.
        file_path (str): Optional field to store the file path on the server (may not be needed).
        uploaded_by (ForeignKey): Optional user who uploaded the log file (related to User model).
        log_type (CharField): Optional field to categorize the log file type (e.g., Apache, access).

    """

    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    file = models.FileField(upload_to="log_files/")
    upload_date = models.DateTimeField(auto_now_add=True)
    file_size = models.BigIntegerField(blank=True, null=True)
    file_path = models.CharField(max_length=255, blank=True)
    uploaded_by = models.ForeignKey(
        User, on_delete=models.CASCADE, blank=True, null=True
    )
    log_type = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        choices=[
            ("apache", "Apache"),
            ("sendmail", "Sendmail"),
            ("ssl", "SSL"),
            ("access", "Access"),
            ("kernel", "Kernel"),
        ],
    )

    def __str__(self):
        return f"{self.source.name} - {self.file_name} ({self.upload_date})"


class LogEntry(models.Model):
    """
    Represents a single log entry parsed from an uploaded log file.

    Args:
        created_by (ForeignKey): Optional user who created the log entry (related to User model).
        source (ForeignKey): Foreign key referencing the LogSource model.
        file (ForeignKey): Foreign key referencing the LogFile model.
        timestamp (DateTimeField): Timestamp of the log message.
        message (TextField): Actual log message content.
        severity (CharField): Optional field for log severity (e.g., low, high).
        ip_address (CharField): Optional IP address extracted from the log message.
        request_details (CharField): Optional field for request details (e.g., method, URL).
        status_code (IntegerField): Optional field for HTTP status code (if applicable).
        response_size (IntegerField): Optional field for response size (if applicable).
        mail_activity (TextField): Optional field for details related to email activity (if applicable).
        src_ip (CharField): Optional source IP address (may be different from ip_address).
        dst_ip (CharField): Optional destination IP address (may be different from ip_address).
        pid (CharField): Optional process ID extracted from the log message.
        msgid (CharField): Optional message ID extracted from the log message (e.g., email).
        host (CharField): Optional hostname extracted from the log message.
        data (JSONField): Optional field to store additional parsed data from the log message.
        raw_data (TextField): Optional field to store the raw log message content.

    """

    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="user_created",
    )
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    file = models.ForeignKey(LogFile, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(default=timezone.now)
    message = models.TextField()
    severity = models.CharField(max_length=20, blank=True, null=True)
    ip_address = models.CharField(max_length=100, blank=True, null=True)
    request_details = models.CharField(max_length=10, blank=True, null=True)
    status_code = models.IntegerField(blank=True, null=True)
    response_size = models.IntegerField(blank=True, null=True)
    mail_activity = models.TextField(null=True, blank=True)
    src_ip = models.CharField(max_length=20, blank=True, null=True)
    dst_ip = models.CharField(max_length=20, blank=True, null=True)
    pid = models.CharField(max_length=20, blank=True, null=True)
    msgid = models.CharField(max_length=20, blank=True, null=True)
    host = models.CharField(max_length=30, blank=True, null=True)
    data = models.JSONField(blank=True)
    raw_data = models.TextField(blank=True)

    def __str__(self):
        return f"{self.source.name} - {self.timestamp}"


class Alert(models.Model):
    """
    Represents a security alert generated based on log analysis rules.

    Args:
        log_entry (ForeignKey): Optional foreign key referencing the LogEntry model (may not be triggered from specific entries).
        severity (CharField): Severity level of the alert (choices: LOW, MEDIUM, HIGH, CRITICAL).
        rule_name (CharField): Name of the rule that triggered the alert.
        description (TextField): Detailed description of the alert.
        triggered_at (DateTimeField): Date and time the alert was triggered (auto-populated).
        is_acknowledged (BooleanField): Flag indicating whether the alert has been acknowledged.
        acknowledged_at (DateTimeField): Optional timestamp for when the alert was acknowledged.
        action_taken (TextField): Optional field to record any actions taken in response to the alert.
        actor (ForeignKey): Optional user who acknowledged the alert (related to User model).

    """

    log_entry = models.ForeignKey(
        LogEntry, on_delete=models.CASCADE, blank=True, null=True
    )
    severity = models.CharField(
        max_length=255,
        choices=[
            ("LOW", "Low"),
            ("MEDIUM", "Medium"),
            ("HIGH", "High"),
            ("CRITICAL", "Critical"),
        ],
        default="LOW",
    )
    rule_name = models.CharField(max_length=255, blank=True)
    description = models.TextField()
    triggered_at = models.DateTimeField(default=timezone.now)
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    action_taken = models.TextField(blank=True, null=True)
    actor = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return f"Alert - {self.description}"


class Report(models.Model):
    """
    Represents a generated security report.

    Args:
        name (str): Name of the report.
        description (str): Optional description of the report.
        generated_at (DateTimeField): Date and time the report was generated (auto-populated).

    """

    name = models.CharField(max_length=100)
    description = models.TextField()
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(
        User, on_delete=models.CASCADE, blank=True, null=True
    )
    content = models.TextField()

    def __str__(self):
        return self.name


class UserActionLog(models.Model):
    """
    Logs user actions within the system for auditing and monitoring purposes.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField()

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"
