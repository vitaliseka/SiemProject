from django.urls import path
from . import views

app_name = "core"

urlpatterns = [
    path("sources/", views.log_sources, name="log_sources"),
    path("source/<id>/", views.log_source, name="log_source"),
    path("add-source/", views.add_log_source, name="add_log_source"),
    path("delete-source/", views.delete_log_source, name="delete_log_source"),
    path("report/<id>/", views.report, name="report"),
    path("reports/", views.reports, name="reports"),
    path("generate_security_report/<user_id>/", views.generate_security_report, name="generate_security_report"),
    path("alerts/", views.alerts, name="alerts"),
    path("alert/<id>/", views.alert, name="alert"),
    path("log-file/<id>/", views.log_file, name="log_file"),
    path("read-file/<id>/", views.read_log, name="read_log"),
    path("run-detectors/<id>/", views.run_detectors, name="run_detectors"),
    path("add-log-file/<id>/", views.add_log_file, name="add_log_file"),
    path("upload-api/", views.handle_uploaded_log, name="handle_uploaded_log"),
    path(
        "acknowledge-alert/<int:alert_id>/",
        views.acknowledge_alert,
        name="acknowledge_alert",
    ),
    path("", views.dashboard, name="dashboard"),
]
