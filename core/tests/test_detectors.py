from django.test import TestCase
from core.models import LogEntry, Alert, LogSource, LogFile
from core.detectors import (
    detect_failed_logins,
    detect_high_error_volume,
)
from django.utils import timezone
from datetime import timedelta


class FailedLoginsDetectionTestCase(TestCase):
    def setUp(self):
        self.time_threshold = timezone.now() - timedelta(minutes=10)
        self.source = LogSource.objects.create(name="Hello")
        self.log_file = LogFile.objects.create(file_name='logfile.log', source=self.source)

        for i in range(6):
            LogEntry.objects.create(
                timestamp=self.time_threshold + timedelta(seconds=i),
                severity="WARNING",
                message="failed login",
                ip_address="127.0.0.1",
                request_details="",
                status_code=401,
                response_size=0,
                mail_activity="",
                host=1234,
                msgid="",
                pid="",
                src_ip="",
                dst_ip="",
                data={},
                raw_data="raw log data",
                source=self.source,
                file=self.log_file,
            )

    def test_detect_failed_logins(self):
        detect_failed_logins()
        self.assertEqual(Alert.objects.count(), 6)
        alert = Alert.objects.first()
        self.assertIn("127.0.0.1", alert.description)
        self.assertEqual(alert.rule_name, "detect_failed_logins")


class HighErrorVolumeDetectionTestCase(TestCase):
    def setUp(self):
        self.time_threshold = timezone.now() - timedelta(minutes=15)
        self.source = LogSource.objects.create(name="Hello2")
        self.log_file = LogFile.objects.create(file_name='test.log', source=self.source)

        for i in range(11):
            LogEntry.objects.create(
                timestamp=self.time_threshold + timedelta(seconds=i),
                severity="ERROR",
                message="Server error",
                ip_address="127.0.0.1",
                request_details="",
                status_code=500,
                response_size=0,
                mail_activity="",
                host=1234,
                msgid="",
                pid="",
                src_ip="",
                dst_ip="",
                data={},
                raw_data="raw log data",
                source=self.source,
                file=self.log_file,
            )

    def test_detect_high_error_volume(self):
        detect_high_error_volume()
        self.assertEqual(Alert.objects.count(), 5)
        alert = Alert.objects.first()
        self.assertIn("500", alert.description)
        self.assertEqual(alert.rule_name, "detect_high_error_volume")


def detect_suspicious_ip_activity():
    blacklist = ["220.228.136.38", "63.158.248.63"]
    
    # Fetch log entries with IPs in the blacklist
    suspicious_entries = LogEntry.objects.filter(ip_address__in=blacklist)
    
    # Log the number of entries found
    print(f"Found {suspicious_entries.count()} suspicious entries")
    
    for entry in suspicious_entries:
        # Create alerts for each suspicious log entry
        Alert.objects.create(
            log_entry=entry,
            rule_name="detect_suspicious_ip_activity",
        )
    
    # Print out the number of alerts created
    print(f"Created {Alert.objects.count()} alerts")


class SuspiciousIPActivityDetectionTestCase(TestCase):
    def setUp(self):
        # Setup for the test
        self.blacklist = ["220.228.136.38", "63.158.248.63"]
        self.source = LogSource.objects.create(name="Hello3")
        self.log_file = LogFile.objects.create(file_name='test.log', source=self.source)

        # Create log entries for each IP in the blacklist
        for ip in self.blacklist:
            LogEntry.objects.create(
                timestamp=timezone.now(),
                severity="INFO",
                message="Suspicious activity detected",
                ip_address=ip,
                request_details="",
                status_code=200,
                response_size=0,
                mail_activity="",
                host="1234",  # Assuming 'host' should be a string
                msgid="",
                pid="",
                src_ip="",
                dst_ip="",
                data={},  # Ensure this matches the field type in your model
                raw_data="raw log data",
                source=self.source,
                file=self.log_file,
            )

    def test_detect_suspicious_ip_activity(self):
        # Run the detection function
        detect_suspicious_ip_activity()
        
        # Verify the number of alerts created
        self.assertEqual(Alert.objects.count(), len(self.blacklist))
        
        # Check that each alert corresponds to a blacklisted IP
        for alert in Alert.objects.all():
            self.assertIn(alert.log_entry.ip_address, self.blacklist)
            self.assertEqual(alert.rule_name, "detect_suspicious_ip_activity")
