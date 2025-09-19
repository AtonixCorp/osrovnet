from celery import shared_task
from django.utils import timezone
from .models import ScheduledReport
from .serializers import ReportDefinitionSerializer
import csv
import io
import json
from django.core.mail import send_mail


@shared_task(bind=True)
def run_scheduled_report(self, schedule_id):
    try:
        schedule = ScheduledReport.objects.get(pk=schedule_id)
    except ScheduledReport.DoesNotExist:
        return {'status': 'not_found'}

    report = schedule.report

    # For now, just serialize the report definition as the "result".
    serializer = ReportDefinitionSerializer(report)
    data = serializer.data

    # Example: create CSV from definition keys (placeholder)
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(['key', 'value'])
    for k, v in data.get('definition', {}).items():
        writer.writerow([k, json.dumps(v)])

    csv_content = csv_buffer.getvalue()

    # Update last_run
    schedule.last_run = timezone.now()
    schedule.save()

    # Send email to recipients if any (recipients stored as json list of emails)
    try:
        recipients = schedule.recipients or []
        if isinstance(recipients, str):
            recipients = json.loads(recipients)
        emails = [r for r in recipients if '@' in r]
        if emails:
            send_mail(
                subject=f"Scheduled Report: {report.name}",
                message="Please find the attached report (CSV) - inline content below:\n\n" + csv_content[:2000],
                from_email=None,
                recipient_list=emails,
                fail_silently=True,
            )
    except Exception:
        # don't fail the task if notifications fail
        pass

    return {'status': 'ok', 'last_run': schedule.last_run.isoformat()}
