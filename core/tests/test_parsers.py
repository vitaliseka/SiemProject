from django.test import TestCase
#from core.parsers import parse_timestamp
from datetime import datetime


def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None

class TimestampParserTestCase(TestCase):
    def test_valid_timestamp(self):
        result = parse_timestamp("Sun Mar 13 00:49:30 2005")
        expected_result = datetime(2005, 3, 13, 0, 49, 30)
        self.assertEqual(result, expected_result)

    def test_invalid_timestamp(self):
        result = parse_timestamp("Invalid Timestamp")
        self.assertIsNone(result)


