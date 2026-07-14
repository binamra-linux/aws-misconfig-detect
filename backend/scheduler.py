"""
Scheduled background scans.

Uses APScheduler's BackgroundScheduler, NOT AsyncIOScheduler: the scan is
blocking boto3 work, and running it on FastAPI's event loop would stall every
request in the process -- including the SSE progress stream -- for the whole scan.
BackgroundScheduler runs jobs in its own thread pool instead.

The job goes through scan_service.try_begin_scan() like every other caller, so a
scheduled scan and a manual one can never run concurrently and corrupt the shared
scan state. If a manual scan is already running, the scheduled one *skips* rather
than queueing -- the next cron tick will pick it up anyway, and stacking scans
would just fight over the same lock.
"""

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from backend import config, scan_service
from backend.notify.email_client import send_new_findings_alert
from backend.scanner import run_full_scan

logger = logging.getLogger(__name__)

_scheduler: Optional[BackgroundScheduler] = None


def run_scheduled_scan() -> None:
    if not scan_service.try_begin_scan("scheduled"):
        logger.info("Skipping scheduled scan -- another scan is already running.")
        return

    try:
        logger.info("Starting scheduled scan.")
        checks = run_full_scan()
        response, new_findings = scan_service.finalize_scan(checks)

        logger.info(
            "Scheduled scan complete: %d finding(s), %d new.",
            len(response["findings"]),
            len(new_findings),
        )

        send_new_findings_alert(
            new_findings=new_findings,
            total=len(response["findings"]),
            score=response["score"],
        )
    except Exception as e:
        logger.error("Scheduled scan failed: %s", e)
    finally:
        scan_service.end_scan()


def start() -> Optional[BackgroundScheduler]:
    """Start the scheduler if enabled. Returns None when disabled."""
    global _scheduler

    if not config.SCAN_SCHEDULE_ENABLED:
        logger.info("Scheduled scans are disabled (SCAN_SCHEDULE_ENABLED=false).")
        return None

    try:
        trigger = CronTrigger.from_crontab(config.SCAN_SCHEDULE_CRON)
    except ValueError as e:
        logger.error("Invalid SCAN_SCHEDULE_CRON %r -- scheduled scans disabled: %s", config.SCAN_SCHEDULE_CRON, e)
        return None

    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        run_scheduled_scan,
        trigger=trigger,
        id="scheduled_scan",
        # Never let scans pile up on top of each other; if the machine was asleep
        # through several triggers, run once on wake rather than replaying a backlog.
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    _scheduler.start()

    logger.info("Scheduled scans enabled (cron: %s).", config.SCAN_SCHEDULE_CRON)
    return _scheduler


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None:
        # wait=False so a reload/shutdown isn't blocked behind an in-flight scan.
        _scheduler.shutdown(wait=False)
        _scheduler = None


def status() -> dict:
    job = _scheduler.get_job("scheduled_scan") if _scheduler else None
    return {
        "enabled": config.SCAN_SCHEDULE_ENABLED,
        "cron": config.SCAN_SCHEDULE_CRON if config.SCAN_SCHEDULE_ENABLED else None,
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
        "alerts_configured": config.alerts_configured(),
        "alert_recipients": config.ALERT_TO if config.alerts_configured() else [],
    }
