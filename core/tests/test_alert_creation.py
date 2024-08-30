from django.test import TestCase
from core.models import LogEntry, Alert, LogSource, LogFile
from core.detectors import create_alert
from django.utils import timezone


class AlertCreationTestCase(TestCase):
    def setUp(self):
        self.source = LogSource.objects.create(name="Hello4")
        self.log_file = LogFile.objects.create(file_name='logfile.log', source=self.source)

        self.log_entry = LogEntry.objects.create(
            timestamp=timezone.now(),
            severity="INFO",
            message="This is a test log entry",
            ip_address="127.0.0.1",
            request_details="GET /test HTTP/1.1",
            status_code=200,
            response_size=1024,
            mail_activity="",
            host=1234,
            msgid="",
            pid="",
            src_ip="127.0.0.1",
            dst_ip="127.0.0.2",
            data={},
            raw_data="raw log data",
            source=self.source,
            file=self.log_file,
        )

    def test_create_alert(self):
        description = "This is a test alert"
        create_alert(self.log_entry, "MEDIUM", "test_rule", description)
        self.assertEqual(Alert.objects.count(), 1)
        alert = Alert.objects.first()
        self.assertEqual(alert.log_entry, self.log_entry)
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertEqual(alert.rule_name, "test_rule")
        self.assertEqual(alert.description, description)
