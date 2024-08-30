from django.contrib import admin
from .models import LogSource, LogFile, LogEntry, Alert, Report, UserActionLog


@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ["name", "description", "hostname", "ip_address", "protocol"]
    search_fields = ["name", "description", "hostname", "ip_address"]


@admin.register(LogFile)
class LogFileAdmin(admin.ModelAdmin):
    list_display = ["source", "file_name", "upload_date", "file_size", "uploaded_by"]
    search_fields = ["source__name", "file_name", "uploaded_by__username"]
    list_filter = ["source", "upload_date"]


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ["source", "file", "timestamp", "message"]
    search_fields = ["source__name", "message", "data"]
    list_filter = ["source", "timestamp"]


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = [
        "log_entry",
        "severity",
        "rule_name",
        "triggered_at",
        "is_acknowledged",
    ]
    search_fields = ["log_entry__message", "rule_name", "description"]
    list_filter = ["severity", "is_acknowledged"]


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["name", "description", "generated_at", "generated_by"]
    search_fields = ["name", "description", "content"]
    list_filter = ["generated_by"]


@admin.register(UserActionLog)
class UserActionLogAdmin(admin.ModelAdmin):
    list_display = ["user", "action", "timestamp"]
    search_fields = ["user__username", "action"]
    list_filter = ["user", "timestamp"]
