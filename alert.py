# alert.py
import logging
import re
from datetime import datetime, timedelta
from sqlalchemy import or_
from database import SessionLocal
from models import AlertRule, AlertHistory, Monitor, Domain

logger = logging.getLogger(__name__)

# Replace the existing get_domain_suffixes function with this:
def get_domain_suffixes(url):
    """
    Generates a list of domain suffixes to search for potential parent monitors.
    e.g. 'lms.courses.bdu.edu.et' -> ['lms.courses.bdu.edu.et', 'courses.bdu.edu.et', 'bdu.edu.et', 'edu.et', 'et']
    e.g. 'user@example.com' -> ['example.com', 'com'] (Handles username/host format)
    """
    try:
        # Remove protocol and path
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # FIX: Handle username/host format (e.g., user@example.com)
        # If '@' exists, we only care about the host part after it.
        if '@' in domain:
            domain = domain.split('@')[-1]

        parts = domain.split(".")
        suffixes = []
        for i in range(len(parts)):
            suffixes.append(".".join(parts[i:]))
        return suffixes
    except:
        return [url]

# Replace the existing get_root_domain helper inside check_service_alerts (or at the top level) with this:
# If it is defined locally inside the function, update it there.
def get_root_domain(u):
    try:
        d = u.replace("https://", "").replace("http://", "").split("/")[0]
        
        # FIX: Handle username/host format
        if '@' in d:
            d = d.split('@')[-1]
            
        p = d.split(".")
        return ".".join(p[-2:]) if len(p) > 2 else d
    except: 
        return u
def check_service_alerts(target_url, current_status, current_latency):
    """
    Evaluates the current monitoring state against user-defined AlertRules.
    Includes Fuzzy Matching for subdomains with typos or Certificate Intermediate strings.
    """
    db = SessionLocal()
    try:
        target_monitor_ids = set()
        user_id_to_check = None
        monitor_id_to_use = None 

        # 1. EXACT MATCH: Try to find an exact monitor entry first
        monitor = db.query(Monitor).filter(Monitor.target_url == target_url).first()
        if monitor:
            target_monitor_ids.add(monitor.id)
            user_id_to_check = monitor.user_id
            monitor_id_to_use = monitor.id

        # 2. SUFFIX SEARCH: If no exact match, try to find a parent monitor
        if not user_id_to_check:
            possible_domains = get_domain_suffixes(target_url)
            
            # Iterate from most specific to least specific
            for domain_candidate in reversed(possible_domains):
                parent_monitor = db.query(Monitor).filter(
                    or_(
                        Monitor.target_url == f"http://{domain_candidate}",
                        Monitor.target_url == f"https://{domain_candidate}",
                        Monitor.target_url == domain_candidate
                    )
                ).first()

                if parent_monitor:
                    target_monitor_ids.add(parent_monitor.id)
                    user_id_to_check = parent_monitor.user_id
                    monitor_id_to_use = parent_monitor.id
                    break 

        # 3. DOMAIN TABLE FALLBACK
        if not user_id_to_check:
            for domain_candidate in reversed(possible_domains):
                domain_entry = db.query(Domain).filter(Domain.domain_name == domain_candidate).first()
                if domain_entry:
                    user_id_to_check = domain_entry.user_id
                    break

        # 4. RULE TABLE FALLBACK (If no Monitor/Domain entry exists)
        if not user_id_to_check:
            norm_url = target_url.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
            matching_rule_for_user = db.query(AlertRule).filter(
                AlertRule.target_url == norm_url,
                AlertRule.type == "service",
                AlertRule.is_active == True
            ).first()

            if matching_rule_for_user:
                user_id_to_check = matching_rule_for_user.user_id

        # If we still can't identify the user, we can't proceed
        if not user_id_to_check:
            return

        # 5. FETCH RULES
        rules = db.query(AlertRule).filter(
            AlertRule.user_id == user_id_to_check,
            AlertRule.type == "service",
            AlertRule.is_active == True
        ).all()

        # --- HELPER: Get Root Domain ---
        def get_root_domain(u):
            try:
                d = u.replace("https://", "").replace("http://", "").split("/")[0]
                if '@' in d: d = d.split('@')[-1]
                p = d.split(".")
                return ".".join(p[-2:]) if len(p) > 2 else d
            except: return u

        current_root_domain = get_root_domain(target_url)

        for rule in rules:
            # --- SMART MATCHING LOGIC ---
            rule_applies = False
            
            # Case A: Exact ID match
            if rule.target_id and rule.target_id in target_monitor_ids:
                rule_applies = True
            
            # Case B: Rule has a specific URL string
            elif rule.target_url:
                clean_rule_url = rule.target_url.replace("https://", "").replace("http://", "").strip().lower().rstrip("/")
                clean_current_url = target_url.replace("https://", "").replace("http://", "").strip().lower().rstrip("/")
                
                # Check if current URL ends with the rule URL (Standard Subdomain)
                if clean_current_url.endswith("." + clean_rule_url) or clean_current_url == clean_rule_url:
                    rule_applies = True
                
                # --- NEW: FUZZY MATCH (CONTAINS) ---
                # Handles "m.testexample.com" matching "example.com" 
                # and "AS207960 Test Intermediate - example.com" matching "example.com"
                elif clean_rule_url in clean_current_url and len(clean_rule_url) > 3:
                    rule_applies = True

                # Fallback: Root domain check
                elif get_root_domain(clean_current_url) == get_root_domain(clean_rule_url):
                    rule_applies = True
            
            # Case C: Global Rule
            elif rule.target_id is None and not rule.target_url:
                rule_applies = True
            
            if not rule_applies:
                continue

            triggered = False
            message = ""

            # --- LOGIC: STATUS DOWN ---
            if rule.condition == "status_down":
                failure_keywords = ["DOWN", "ERROR", "REFUSED", "TIMEOUT", "NOT FOUND", "CRITICAL"]
                if any(kw in current_status for kw in failure_keywords):
                    triggered = True
                    message = f"CRITICAL: {target_url} reported status '{current_status}'. (Rule: {rule.name})"

            # --- LOGIC: HIGH LATENCY ---
            elif rule.condition == "response_time_high":
                thresh_str = rule.threshold if rule.threshold else ">1000"
                
                if thresh_str.strip().isdigit():
                    thresh_str = ">" + thresh_str

                operator = ">"
                limit = 1000

                if ">=" in thresh_str:
                    operator = ">="; limit = int(thresh_str.replace(">=", ""))
                elif ">" in thresh_str:
                    operator = ">"; limit = int(thresh_str.replace(">", ""))
                elif "<=" in thresh_str:
                    operator = "<="; limit = int(thresh_str.replace("<=", ""))
                elif "<" in thresh_str:
                    operator = "<"; limit = int(thresh_str.replace("<", ""))

                is_breached = False
                if operator == ">=" and current_latency >= limit: is_breached = True
                elif operator == ">" and current_latency > limit: is_breached = True
                elif operator == "<=" and current_latency <= limit: is_breached = True
                elif operator == "<" and current_latency < limit: is_breached = True

                if is_breached:
                    triggered = True
                    message = f"WARNING: {target_url} latency {current_latency:.2f}ms > {limit}ms (Rule: {rule.name})"
            elif rule.condition == "smart_anomaly":
                ml_keywords = ["Unstable", "WARNING: High Latency", "CRITICAL: Pattern Breakdown", "WARNING: Drifting"]
                if any(kw in current_status for kw in ml_keywords):
                  triggered = True
                  message = (f"SMART ANOMALY DETECTED: {target_url} behavior deviates significantly from baseline. "
                  f"System Status: '{current_status}'. (Rule: {rule.name})")

            # --- DEBOUNCE & SAVE ---
            if triggered:
                # Check for recent alerts. 
                recent_alert = db.query(AlertHistory).filter(
                    AlertHistory.rule_id == rule.id,
                    AlertHistory.source_id == monitor_id_to_use,
                    AlertHistory.triggered_at > datetime.utcnow() - timedelta(minutes=30),
                    AlertHistory.message.like(f"%{target_url}%")
                ).first()

                if not recent_alert:
                    new_alert = AlertHistory(
                        user_id=user_id_to_check,
                        rule_id=rule.id,
                        source_type="monitor",
                        source_id=monitor_id_to_use,
                        message=message,
                        severity=rule.severity,
                        channel=rule.channel,
                        status="sent"
                    )
                    db.add(new_alert)
                    db.commit()
                    logger.info(f"ALERT TRIGGERED: {message}")
                else:
                    logger.debug(f"ALERT DEBOUNCED: Rule {rule.id} for {target_url}")

    except Exception as e:
        logger.error(f"Alert Logic Error: {e}")
        db.rollback()
    finally:
        db.close()