import asyncio
import csv
import time
from datetime import datetime

import httpx

from database import SessionLocal
from models import Monitor

# Configuration: How long to run the audit (in seconds)
AUDIT_DURATION = 300
CHECK_INTERVAL = 1.5
GROUND_TRUTH_TIMEOUT = httpx.Timeout(connect=8.0, read=15.0, write=10.0, pool=8.0)


async def probe_target(client: httpx.AsyncClient, target_url: str):
    """
    Mirror the application's probing semantics closely so the ground truth
    measures the same thing the monitoring system claims to detect.
    """
    response = await client.head(target_url)
    if response.status_code in {301, 302, 303, 307, 308, 403, 405}:
        response = await client.get(target_url, headers={"Range": "bytes=0-0"})
    return response


def classify_real_up(status_code: int) -> bool:
    """
    Match the monitor's notion of service availability.
    """
    if status_code >= 500:
        return False
    if status_code in {401, 403, 429}:
        return True
    if 400 <= status_code < 500:
        return False
    return True


async def audit_target(client: httpx.AsyncClient, target_url: str):
    checked_at = datetime.utcnow().isoformat()
    try:
        response = await probe_target(client, target_url)
        return {
            "timestamp": checked_at,
            "target_url": target_url,
            "status_code": response.status_code,
            "is_real_up": classify_real_up(response.status_code),
            "error": "",
        }
    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
        return {
            "timestamp": checked_at,
            "target_url": target_url,
            "status_code": "",
            "is_real_up": False,
            "error": "timeout",
        }
    except httpx.ConnectError:
        return {
            "timestamp": checked_at,
            "target_url": target_url,
            "status_code": "",
            "is_real_up": False,
            "error": "connect_error",
        }
    except Exception as exc:
        return {
            "timestamp": checked_at,
            "target_url": target_url,
            "status_code": "",
            "is_real_up": False,
            "error": str(exc)[:80],
        }


async def run_audit():
    print("--- STARTING GROUND TRUTH COLLECTION ---")

    db = SessionLocal()
    try:
        monitors = db.query(Monitor).filter(Monitor.is_active == True).all()
        targets = sorted({m.target_url for m in monitors if m.target_url})
    finally:
        db.close()

    if not targets:
        print("No active monitors found.")
        return

    print(f"Auditing {len(targets)} targets for {AUDIT_DURATION} seconds...")

    with open("ground_truth.csv", mode="w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["timestamp", "target_url", "status_code", "is_real_up", "error"],
        )
        writer.writeheader()

        start_time = time.time()
        async with httpx.AsyncClient(timeout=GROUND_TRUTH_TIMEOUT, follow_redirects=True) as client:
            while (time.time() - start_time) < AUDIT_DURATION:
                results = await asyncio.gather(*(audit_target(client, target) for target in targets))
                writer.writerows(results)
                file.flush()
                await asyncio.sleep(CHECK_INTERVAL)

    print("--- AUDIT COMPLETE. File saved as 'ground_truth.csv' ---")


if __name__ == "__main__":
    asyncio.run(run_audit())
