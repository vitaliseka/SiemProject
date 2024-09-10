from django.shortcuts import render, redirect
from django.http import HttpResponse
from core.models import LogSource, LogFile, LogEntry, Alert, Report, UserActionLog
from django.contrib import messages
from core.parsers import (
    parse_apache_log,
    parse_sendmail_log,
    parse_ssl_log,
    parse_access_log,
    parse_kernel_log,
    parse_ssl_log,
)
from core.detectors import (
    detect_failed_logins,
    detect_high_error_volume,
    detect_suspicious_ip_activity,
    detect_sql_injection,
    detect_xss_attempts,
    detect_port_scanning,
    detect_brute_force,
    detect_unauthorized_access,
    detect_dos_attacks,
    detect_targeted_dos,
    detect_unusual_mail_activity,
    detect_spam_phishing,
)
import json
from django.db.models import Count
import re
from collections import defaultdict
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.contrib.auth.models import User



"""
By default, Django protects against CSRF (Cross-Site Request Forgery) attacks. 
This decorator disables that protection for this specific view.
"""


@csrf_exempt
def handle_uploaded_log(request):
    """
    This function checks if the request method is POST and there's a file uploaded through the file key.
    It retrieves details like file name, size, path, and source.
    A LogFile object is created and saved.
    Success or error messages are returned depending on the upload status.
    """
    if request.method == "POST" and request.FILES["file"]:
        uploaded_file = request.FILES["file"]
        file_name = uploaded_file.name
        file_size = uploaded_file.size
        file_path = f"uploads/{file_name}"
        source_id = request.POST["source_id"]
        source = LogSource.objects.get(id=source_id)

        log_file = LogFile(
            file=uploaded_file,
            file_name=file_name,
            file_size=file_size,
            file_path=file_path,
            source=source,
        )
        log_file.save()
        return HttpResponse("File uploaded successfully.")
    else:
        return HttpResponse("No file found or method not allowed.")


# This function handles acknowledging an alert.
@login_required  # This decorator ensures only authenticated users can access this view
def acknowledge_alert(request, alert_id):
    """
    This function retrieves the alert object based on the provided alert_id.
    It defines the template to be used (acknowledge.html) and creates a context dictionary with the user and alert objects.
    If the request method is POST, it retrieves the action_taken from the request data and sets it along with the acknowledging user (actor).
    It also marks the alert as acknowledged with a timestamp.
    The function redirects to the alert detail view (core:alert) after updating the alert.
    For GET requests, it renders the acknowledge.html template with the context data
    """
    alert = Alert.objects.get(id=alert_id)
    template = "acknowledge.html"
    context = {
        "user": request.user,
        "alert": alert,
    }

    if request.method == "POST":
        action_taken = request.POST["action_taken"]
        actor = request.user

        alert.action_taken = action_taken
        alert.actor = actor
        alert.is_acknowledged = True
        alert.acknowledged_at = timezone.now()
        alert.save()

        return redirect("core:alert", id=alert_id)

    return render(request, template, context)


@login_required
def dashboard(request):

    user = (
        request.user
    )  # This retrieves the current user from the request object (request.user).
    template = (
        "dashboard.html"  # Define the template to be used for rendering the dashboard.
    )
    # 1. Total log entries
    total_log_entries = (
        LogEntry.objects.count()
    )  # Counts the total number of log entries using

    # 2. Active alerts (unacknowledged alerts)
    active_alerts = Alert.objects.filter(is_acknowledged=False).count()

    # 3. Overall system health (simplified as the percentage of unacknowledged alerts)
    """
    Calculate a simplified health metric based on the percentage of unacknowledged alerts. 
    This avoids division by zero by checking the total alert count before calculating the percentage.
    """
    total_alerts = Alert.objects.count()
    system_health = (
        (total_alerts - active_alerts) / total_alerts * 100 if total_alerts > 0 else 100
    )

    # 4. Detection trends (detection rules by count over days)
    """
    Retrieve the count of alerts triggered by each detection rule over the past 7 days using clever Django ORM queries. 
    This filters alerts based on the triggered_at timestamp, groups them by rule_name, and orders them by count in descending order.
    """
    detection_trends = (
        Alert.objects.filter(triggered_at__gte=timezone.now() - timedelta(days=7))
        .values("rule_name")
        .annotate(count=Count("rule_name"))
        .order_by("-count")
    )

    # 5. Alert trends (alerts over days)
    """
    Retrieve the daily count of alerts over the past 7 days. 
    This uses similar logic with extra(select={"day": "date(triggered_at)"}) to extract the date from the triggered_at timestamp and groups by day.
    """
    alert_trends = (
        Alert.objects.filter(triggered_at__gte=timezone.now() - timedelta(days=7))
        .extra(select={"day": "date(triggered_at)"})
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    # 6. Alerts by severity (pie chart)
    alerts_by_severity = Alert.objects.values("severity").annotate(
        count=Count("severity")
    )

    # 7. Suspicious IP activity (IP by activity counts)
    """
    Rank the top 10 IP addresses based on their activity count in the logs 
    """
    suspicious_ip_activity = (
        LogEntry.objects.values("ip_address")
        .annotate(count=Count("ip_address"))
        .order_by("-count")[:10]
    )
    suspicious_ip_activity = [s for s in suspicious_ip_activity if s["ip_address"]]

    """
    Retrieve the count of alerts originating from each log source using
    """
    alerts_by_source = (
        Alert.objects.values("log_entry__source__name")
        .annotate(alert_count=Count("id"))
        .order_by("-alert_count")
    )
    alerts_by_source = list(alerts_by_source)
    print(alerts_by_source)
    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "user": user,
        "total_log_entries": total_log_entries,
        "active_alerts": active_alerts,
        "system_health": system_health,
        "detection_trends": detection_trends,
        "alert_trends": alert_trends,
        "alerts_by_severity": alerts_by_severity,
        "suspicious_ip_activity": suspicious_ip_activity,
        "alerts_by_source": alerts_by_source,
        "alerts": alerts,
    }
    return render(request, template, context)


@login_required
def log_sources(request):
    """
    Displays a paginated list of log sources for the current user.
    """
    user = request.user
    log_sources = LogSource.objects.filter(added_by=user)

    # We use the django Paginator object since we anticipate a large number of log sources
    paginator = Paginator(log_sources, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "user": user,
        "log_sources": log_sources,
        "page_obj": page_obj,
        "alerts": alerts,
    }
    template = "log_sources.html"
    return render(request, template, context)


@login_required
def log_source(request, id):
    """
    Displays a paginated list of log files for a specific log source.
    """
    log_source = LogSource.objects.get(id=id)
    log_files = LogFile.objects.filter(source=log_source)

    # We use the django Paginator object since we anticipate a large number of log files within any given source

    paginator = Paginator(log_files, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "log_source": log_source,
        "log_files": log_files,
        "page_obj": page_obj,
        "alerts": alerts,
    }
    template = "log_files.html"
    return render(request, template, context)


@login_required
def add_log_source(request):
    user = request.user
    # Handles form submission
    if request.method == "POST":
        name = request.POST["name"]
        description = request.POST["description"]
        hostname = request.POST["hostname"]
        ip_address = request.POST["ip_address"]
        protocol = request.POST["protocol"]
        log_format = request.POST["log_format"]

        # Create a new LogSource object with form data

        log_source = LogSource.objects.create(
            name=name,
            description=description,
            hostname=hostname,
            ip_address=ip_address,
            protocol=protocol,
            log_format=log_format,
            added_by=user,  # Set the creator as the current user
        )
        # Redirect to the log sources list view after successful creation
        return redirect("core:log_sources")
    else:  # Handles GET requests for the form
        template = "log_source_add.html"
        alerts = Alert.objects.order_by('-triggered_at')[:5]

        context = {
            "user": user,
            "alerts": alerts,
        }
        return render(request, template, context)


@login_required
def delete_log_source(request, id):
    user = request.user
    # Ensure the user trying to delete owns the log source
    log_source = LogSource.objects.get(id=id, added_by=user)
    log_source.delete()  # Delete the log source object
    return redirect("core:log_sources")  # Redirect back to log sources list


@login_required
def add_log_file(request, id):
    user = request.user  # It retrieves the current user
    source = LogSource.objects.get(
        id=id
    )  # fetches the LogSource object based on the provided id from the URL.

    if request.method == "POST":
        """
        The code checks if the request method is POST (form submission).
        It uses a try-except block to handle potential errors during file upload
        """

        try:
            file = request.FILES["file"]
            file_name = file.name
            file_size = file.size
            file_path = f"uploads/{file_name}"
        except KeyError:
            messages.error(request, "No file uploaded or invalid form submission.")
            return redirect("core:add_log_file")

        """
        If the file upload is successful, 
        it creates a new LogFile object with details and sets the current user as the one who uploaded it.
        """

        log_file = LogFile.objects.create(
            source=source,
            file=file,
            file_name=file_name,
            file_size=file_size,
            file_path=file_path,
            uploaded_by=user,
        )
        messages.success(request, f"Log file '{file_name}' uploaded successfully.")
        return redirect(
            "core:log_source", id=source.id
        )  # redirects to the log source detail view (core:log_source) passing the source ID to display the uploaded file.
    else:
        # If the request method is not POST, it assumes it's a GET request to display the upload form.
        template = "upload_log.html"
        alerts = Alert.objects.order_by('-triggered_at')[:5]

        context = {
            "user": user,
            "source": source,
            "alerts": alerts,
        }
        return render(request, template, context)


@login_required
def log_file(request, id):
    """
    It fetches the LogFile object based on the provided id from the URL.
    Retrieves all LogEntry objects associated with the retrieved LogFile.
    """
    log_file = LogFile.objects.get(id=id)
    log_entries = LogEntry.objects.filter(file=log_file)

    # Checks if the first LogEntry has request_details and sets show_request_details accordingly.
    if log_entries and log_entries[0].request_details:
        show_request_details = True
    else:
        show_request_details = False

    # Checks if the first LogEntry has mail_activity and sets show_mail_activity accordingly.
    if log_entries and log_entries[0].mail_activity:
        show_mail_activity = True
    else:
        show_mail_activity = False

    # Implements pagination for the log_entries using Paginator.
    paginator = Paginator(log_entries, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "log_file": log_file,
        "log_entries": log_entries,
        "show_request_details": show_request_details,
        "show_mail_activity": show_mail_activity,
        "page_obj": page_obj,
        "alerts": alerts,
    }

    template = "log_entries.html"
    return render(request, template, context)


@login_required
def alerts(request):
    """
    A page displaying the alerts in the database.
    """
    user = request.user  # Retrieves the current user from the request.
    alerts = Alert.objects.all()  # Fetches all Alert objects from the database.

    paginator = Paginator(alerts, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "user": user,
        "alerts": alerts,
        "page_obj": page_obj,
    }
    template = "alerts.html"
    return render(request, template, context)


@login_required
def alert(request, id):
    """
    This view function named alert that displays details of a specific alert.
    """
    user = request.user
    alert = Alert.objects.get(
        id=id
    )  # Fetches the Alert object based on the provided id from the URL.
    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "user": user,
        "alert": alert,
        "alerts": alerts,
    }
    template = "alert.html"
    return render(request, template, context)


@login_required
def generate_security_report(request, user_id):
    """
    Generates a security report based on the current alerts in the system.

    Args:
        user (User): The user generating the report.

    Returns:
        Report: The generated report object.
    """

    # Gather alerts
    alerts = Alert.objects.all()

    # Calculate statistics
    severity_counts = alerts.values('severity').annotate(count=Count('severity'))
    rule_counts = alerts.values('rule_name').annotate(count=Count('rule_name'))
    top_ips = alerts.values('log_entry__ip_address').annotate(count=Count('log_entry__ip_address')).order_by('-count')[:5]

    # Summarize alert data in HTML format
    alert_summary = ""
    for alert in alerts:
        alert_summary += f"""
            <tr>
                <td>{alert.id}</td>
                <td>{alert.log_entry.ip_address}</td>
                <td>{alert.severity}</td>
                <td>{alert.rule_name}</td>
                <td>{alert.triggered_at}</td>
            </tr>
        """

    # Create the report content in HTML format
    report_content = f"""
        <html>
        <head>
            <style>
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                table, th, td {{
                    border: 1px solid black;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
            </style>
        </head>
        <body>
            <p><b>Generated on:</b> {timezone.now()}</p>

            <h2><b>Total Alerts:</b> {alerts.count()}</h2>

            <h3>Alert Severity Distribution:</b></h3>
            <ul>
    """

    for severity in severity_counts:
        report_content += f"<li><b>{severity['severity']}:</b> {severity['count']}</li>"
    
    report_content += "</ul><h3 class='text-2xl font-bold'>Alert Rule Distribution:</h3><ul>"
    
    for rule in rule_counts:
        report_content += f"<li><b>{rule['rule_name']}:</b> {rule['count']}</li>"
    
    report_content += "</ul><h3 class='font-bold'>Top Suspicious IPs:</h3><ul>"
    
    for ip in top_ips:
        report_content += f"<li><b>IP Address:</b> {ip['log_entry__ip_address']} - {ip['count']} alerts</li>"
    
    report_content += f"""
            </ul>

            <h3>Alert Details:</h3>
            <table>
                <thead>
                    <tr>
                        <th>Alert ID</th>
                        <th>IP Address</th>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_summary}
                </tbody>
            </table>
        </body>
        </html>
    """

    current_time = timezone.now()
    formatted_time = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"Security_Report_{formatted_time}"
    description = "Report generated for recent security alerts"

    user = User.objects.get(id=user_id)

    # Create and save the report
    report = Report.objects.create(
        name=report_name,
        description=description,
        generated_by=user,
        content=report_content,
    )

    return redirect("core:report", id=report.id)



@login_required
def reports(request):
    """
    Fetches all Report objects generated by the current user.
    """
    user = request.user
    reports = Report.objects.filter(generated_by=user)
    paginator = Paginator(reports, 30)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "user": user,
        "reports": reports,
        "page_obj": page_obj,
        "alerts": alerts,
    }
    template = "reports.html"
    return render(request, template, context)


@login_required
def report(request, id):
    """
    Fetches a Report object.
    """
    user = request.user
    report = Report.objects.get(id=id)
    alerts = Alert.objects.order_by('-triggered_at')[:5]

    context = {
        "user": user,
        "report": report,
        "alerts": alerts,
    }
    template = "report.html"
    return render(request, template, context)


def save_log_entry(log_line, source, file):
    # Unified function to save log entries to Django model
    parsers = [
        parse_access_log,
        parse_apache_log,
        parse_sendmail_log,
        parse_ssl_log,
        parse_kernel_log,
    ]
    date_formats = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%b %d %H:%M:%S",
        "%d/%m/%y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
    ]

    log_entry_data = None
    timestamp = None

    # Try to parse log entry using each parser
    for parser in parsers:
        log_entry_data = parser(log_line)
        if log_entry_data:
            break

    if not log_entry_data:
        # Log entry data could not be parsed by any parser
        print(f"Error: Unable to parse log entry: {log_line}")
        return

    # Try to parse timestamp using each date format
    timestamp_str = log_entry_data.get("timestamp")
    for date_format in date_formats:
        try:
            timestamp = datetime.strptime(timestamp_str, date_format)
            break
        except ValueError:
            continue
    else:
        # If no valid timestamp format is found, handle the error
        print(f"Error: Unable to parse timestamp from: {timestamp_str}")
        return

    # Create LogEntry instance
    log_entry = LogEntry(
        timestamp=timestamp,
        severity=log_entry_data.get("log_level", "INFO"),
        message=log_entry_data.get("message", ""),
        ip_address=log_entry_data.get("client_ip", log_entry_data.get("src_ip", "")),
        request_details=log_entry_data.get("request_details", ""),
        status_code=int(log_entry_data.get("status", 0)),
        response_size=int(log_entry_data.get("size", 0)),
        mail_activity=log_entry_data.get("details", {}),
        host=log_entry_data.get("host", ""),  # Assuming host is integer
        msgid=log_entry_data.get("msgid", ""),
        pid=log_entry_data.get("pid", ""),
        src_ip=log_entry_data.get("src_ip", ""),
        dst_ip=log_entry_data.get("dst_ip", ""),
        data=log_entry_data,  # Store full data for reference
        raw_data=log_line,  # Store raw log line for reference
        source=source,
        file=file,
    )

    # Additional handling if request_details is empty
    if log_entry.request_details == "":
        log_entry.request_details = (
            f"{log_entry_data.get('method', '')} "
            f"{log_entry_data.get('path', '')} "
            f"{log_entry_data.get('protocol', '')} "
            f"{log_entry_data.get('referrer', '')} "
            f"{log_entry_data.get('user_agent', '')}"
        )

    # Save LogEntry instance
    log_entry.save()


@login_required
def read_log(request, id):
    # Retrieves a LogFile instance based on the provided ID.
    log_file = LogFile.objects.get(id=id)
    with open(log_file.file.path, "r") as f:  # Opens the log file in read mode.
        for line in f:  # Iterates over each line in the file.
            save_log_entry(
                line, log_file.source, log_file
            )  # Call save_log_entry function with the line, log source, and log file as arguments.
    return redirect("core:log_file", id=id)


@login_required
def run_detectors(request, id):
    """
    Runs various detection algorithms on log data.

    Args:
        request: The HTTP request object.
        id: The ID of the log file being processed.

    Returns:
        A redirect to the log file detail page.
    """
    detect_failed_logins()  # Detect failed login attempts
    detect_high_error_volume()  # Detect unusually high error rates
    detect_suspicious_ip_activity()  # Detect suspicious IP addresses
    detect_sql_injection()  # Detect SQL injection attempts
    detect_xss_attempts()  # Detect cross-site scripting attempts
    detect_port_scanning()  # Detect port scanning activity
    detect_brute_force()  # Detect brute force attacks
    detect_unauthorized_access()  # Detect unauthorized access attempts
    detect_dos_attacks()  # Detect denial-of-service attacks
    detect_targeted_dos()  # Detect targeted denial-of-service attacks
    detect_unusual_mail_activity()  # Detect unusual email activity
    detect_spam_phishing()  # Detect spam and phishing attempts

    return redirect("core:log_file", id=id)
