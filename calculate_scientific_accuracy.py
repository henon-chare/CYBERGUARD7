import pandas as pd

from database import SessionLocal
from models import Monitor, MonitorLog

# Allow a realistic matching window because ground-truth collection and
# monitor logging are asynchronous and may not line up within 1-2 seconds.
TIME_WINDOW_SECONDS = 10


def load_ground_truth():
    try:
        df = pd.read_csv("ground_truth.csv")
    except FileNotFoundError:
        print("ERROR: ground_truth.csv not found. Run collect_ground_truth.py first.")
        return None

    if df.empty:
        print("ERROR: ground_truth.csv is empty.")
        return None

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["target_url"] = df["target_url"].astype(str).str.strip()
    df["is_real_up"] = (
        df["is_real_up"]
        .astype(str)
        .str.strip()
        .str.lower()
        .map({"true": True, "false": False})
    )
    df = df.dropna(subset=["timestamp", "target_url", "is_real_up"])
    return df


def load_system_logs(truth_df: pd.DataFrame):
    db = SessionLocal()
    try:
        min_time = truth_df["timestamp"].min() - pd.Timedelta(seconds=TIME_WINDOW_SECONDS)
        max_time = truth_df["timestamp"].max() + pd.Timedelta(seconds=TIME_WINDOW_SECONDS)

        logs = (
            db.query(MonitorLog, Monitor)
            .join(Monitor)
            .filter(MonitorLog.checked_at >= min_time, MonitorLog.checked_at <= max_time)
            .all()
        )
    finally:
        db.close()

    log_data = [
        {
            "timestamp": log.checked_at,
            "target_url": str(monitor.target_url).strip(),
            "system_says_up": bool(log.is_up),
            "status_code": log.status_code,
        }
        for log, monitor in logs
    ]

    if not log_data:
        return pd.DataFrame(columns=["timestamp", "target_url", "system_says_up", "status_code"])

    logs_df = pd.DataFrame(log_data)
    logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"], errors="coerce")
    logs_df = logs_df.dropna(subset=["timestamp", "target_url"])
    return logs_df


def calculate_metrics():
    truth_df = load_ground_truth()
    if truth_df is None:
        return

    logs_df = load_system_logs(truth_df)
    if logs_df.empty:
        print("No system logs found in the same time period.")
        return

    # merge_asof requires the join key to be globally sorted, and when `by`
    # is used each group must also be in timestamp order.
    truth_df = truth_df.sort_values(["timestamp", "target_url"]).reset_index(drop=True)
    logs_df = logs_df.sort_values(["timestamp", "target_url"]).reset_index(drop=True)

    matched_df = pd.merge_asof(
        truth_df,
        logs_df,
        on="timestamp",
        by="target_url",
        direction="nearest",
        tolerance=pd.Timedelta(seconds=TIME_WINDOW_SECONDS),
    )

    matched_count = matched_df["system_says_up"].notna().sum()
    unmatched_count = len(matched_df) - matched_count

    matched_df = matched_df.dropna(subset=["system_says_up"]).copy()
    if matched_df.empty:
        print("No overlapping data found. Increase the time window or recollect truth data.")
        return

    tp = int(((matched_df["is_real_up"] == False) & (matched_df["system_says_up"] == False)).sum())
    tn = int(((matched_df["is_real_up"] == True) & (matched_df["system_says_up"] == True)).sum())
    fp = int(((matched_df["is_real_up"] == True) & (matched_df["system_says_up"] == False)).sum())
    fn = int(((matched_df["is_real_up"] == False) & (matched_df["system_says_up"] == True)).sum())

    total_predictions = tp + tn + fp + fn
    accuracy = (tp + tn) / total_predictions if total_predictions else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"Comparing {len(truth_df)} truth points against {len(logs_df)} system logs...")
    print(f"Matched truth rows: {matched_count}")
    print(f"Unmatched truth rows skipped: {unmatched_count}")

    print("\n" + "=" * 50)
    print("       SCIENTIFIC ACCURACY REPORT")
    print("=" * 50)
    print(f"True Positives (Detected Down correctly): {tp}")
    print(f"True Negatives (Detected Up correctly):  {tn}")
    print(f"False Positives (False Alarms):          {fp}")
    print(f"False Negatives (Missed Outages):        {fn}")
    print("-" * 50)
    print(f"Accuracy:   {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"Precision:  {precision:.4f} (Of all DOWN alerts, how many were real?)")
    print(f"Recall:     {recall:.4f} (Did we catch all real outages?)")
    print(f"F1 Score:   {f1_score:.4f} (Balance between Precision and Recall)")
    print("=" * 50)


if __name__ == "__main__":
    calculate_metrics()
