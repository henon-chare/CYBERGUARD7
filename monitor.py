# monitor.py
import asyncio
import time
import os
import joblib 
from typing import List, Dict
import httpx
import numpy as np
import json
import pickle # ADDED: For pickling sklearn models

# --- DEEP LEARNING IMPORTS ---
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model # type: ignore
from tensorflow.keras.layers import LSTM, Dense, Dropout, RepeatVector, TimeDistributed
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest

# ADDED IMPORT FOR ALERTS
from alert import check_service_alerts

# ADDED IMPORTS FOR PERSISTENCE
from database import SessionLocal
from models import MonitorModelState

# --- NEW IMPORTS FOR MONITOR LOGGING ---
# FIX: Added Incident to this import line
from models import Monitor, MonitorLog, Incident 
from datetime import datetime
from urllib.parse import urlparse # ADDED IMPORT


# --- CONFIGURATION ---
CRITICAL_LATENCY_LIMIT_MS = 5000.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(BASE_DIR, "saved_models")
ISO_TRAINING_SIZE = 30
LSTM_TIMESTEPS = 20
LSTM_TRAINING_SIZE = 60

os.makedirs(SAVE_DIR, exist_ok=True)

# ================= PERSISTENCE HELPERS =================
def save_detector_state(target_url, detector, detector_type):
    """Saves the detector state to the database."""
    db = SessionLocal()
    try:
        state_entry = db.query(MonitorModelState).filter(
            MonitorModelState.target_url == target_url,
            MonitorModelState.model_type == detector_type
        ).first()

        params_json = None
        model_blob = None

        if detector_type == "smart_detector":
            params_json = json.dumps(detector.to_state_dict())
        
        elif detector_type == "isolation_forest":
            params_json = json.dumps(detector.to_state_dict())
            if detector.is_trained:
                model_blob = detector.get_model_blob()
        
        elif detector_type == "lstm_metadata":
            # LSTM saves heavy files to disk, but we save metadata here
            params_json = json.dumps({
                "threshold": detector.threshold,
                "is_trained": detector.is_trained
            })

        if state_entry:
            state_entry.parameters_json = params_json
            state_entry.model_blob = model_blob
            state_entry.updated_at = datetime.utcnow()
        else:
            new_state = MonitorModelState(
                target_url=target_url,
                model_type=detector_type,
                parameters_json=params_json,
                model_blob=model_blob
            )
            db.add(new_state)
        
        db.commit()
    except Exception as e:
        print(f"[ERROR] Failed to save state for {target_url}: {e}")
        db.rollback()
    finally:
        db.close()

def load_detector_state(target_url, detector_type):
    """Loads the detector state from the database."""
    db = SessionLocal()
    try:
        state_entry = db.query(MonitorModelState).filter(
            MonitorModelState.target_url == target_url,
            MonitorModelState.model_type == detector_type
        ).first()
        return state_entry
    except Exception as e:
        print(f"[ERROR] Failed to load state for {target_url}: {e}")
        return None
    finally:
        db.close()

# ================= MONITOR LOGGING HELPER =================
def save_monitor_log_entry(target_url: str, status_code: int, response_time: float, is_up: bool):
    """
    Persists a single check result to the monitor_logs table.
    """
    db = SessionLocal()
    try:
        # 1. Find the Monitor ID associated with this target URL
        monitor = db.query(Monitor).filter(Monitor.target_url == target_url).first()
        
        # Only log if this URL is actually being tracked in the Monitor table
        if monitor:
            # Persist the exact host being checked, including subdomains.
            clean_domain = (urlparse(target_url).hostname or target_url).lower()

            log_entry = MonitorLog(
                monitor_id=monitor.id,
                status_code=status_code,
                response_time=response_time,
                is_up=is_up,
                checked_at=datetime.utcnow(),
                domain=clean_domain  # <--- THIS LINE SAVES THE DOMAIN
            )
            db.add(log_entry)
            db.commit()
    except Exception as e:
        print(f"[ERROR] Failed to save log for {target_url}: {e}")
        db.rollback()
    finally:
        db.close()

# monitor.py - Replace handle_incident_tracking()

def handle_incident_tracking(target_url: str, current_status: str, is_down: bool):
    """
    Creates or resolves Incident records based on state transitions.
    """
    db = SessionLocal()
    try:
        # Persist the exact host that failed, including subdomains.
        clean_domain = (urlparse(target_url).hostname or target_url).lower()

        # Determine error type
        error_type = "Unknown"
        status_upper = current_status.upper()
        
        if "TIMEOUT" in status_upper:
            error_type = "Timeout"
        elif "CONNECTION REFUSED" in status_upper:
            error_type = "Connection Refused"
        elif "SERVER DOWN" in status_upper or "500" in status_upper:
            error_type = "Server Error (5xx)"
        elif "PROTECTED" in status_upper or "AUTH REQUIRED" in status_upper:
            error_type = "Protected Resource"
        elif "CLIENT ERROR" in status_upper or "404" in status_upper:
            error_type = "Client Error (4xx)"
        elif "CRITICAL" in status_upper or "PATTERN BREAKDOWN" in status_upper:
            error_type = "Critical ML Anomaly"
        elif "WARNING" in status_upper or "ANOMALY" in status_upper:
            error_type = "Performance Warning"

        # Find or create Monitor record
        monitor = db.query(Monitor).filter(Monitor.target_url == target_url).first()
        if not monitor:
            # AUTO-CREATE Monitor if it doesn't exist
            monitor = Monitor(
                target_url=target_url,
                user_id=1,  # Default user
                is_active=True
            )
            db.add(monitor)
            db.commit()
            db.refresh(monitor)
            print(f"[MONITOR] Auto-created monitor record for {clean_domain}")

        # Check for existing ONGOING incident
        ongoing_incident = db.query(Incident).filter(
            Incident.monitor_id == monitor.id,
            Incident.status == "Ongoing"
        ).order_by(Incident.started_at.desc()).first()

        # Handle DOWN transition
        if is_down:
            if not ongoing_incident:
                new_incident = Incident(
                    monitor_id=monitor.id,
                    domain=clean_domain,
                    status="Ongoing",
                    error_type=error_type,
                    started_at=datetime.utcnow()
                )
                db.add(new_incident)
                db.commit()
                print(f"[INCIDENT] OPENED for {clean_domain}: {error_type}")

        # Handle UP transition
        else:
            if ongoing_incident:
                now = datetime.utcnow()
                ongoing_incident.status = "Resolved"
                ongoing_incident.ended_at = now
                duration = (now - ongoing_incident.started_at).total_seconds()
                ongoing_incident.duration_seconds = int(duration)
                db.commit()
                print(f"[INCIDENT] RESOLVED for {clean_domain}: Duration={int(duration)}s")

    except Exception as e:
        print(f"[ERROR] Incident tracking failed for {target_url}: {e}")
        db.rollback()
    finally:
        db.close()

# --- 1. SMART DETECTOR (EWMA) ---
# Logic taken from your requested snippet
class SmartDetector:
    """
    Uses Exponentially Weighted Moving Average (EWMA) for adaptive anomaly detection.
    """
    def __init__(self, alpha=0.2, threshold=2.5):
        self.alpha = alpha  # Smoothing factor
        self.threshold = threshold # Standard deviations
        self.ema = 0.0  
        self.emsd = 1.0  # Exponential Moving Standard Deviation
        self.is_initialized = False
        self.consecutive_anomalies = 0
        self.required_failures = 3  # Need 3 bad pings in a row

    # --- PERSISTENCE METHODS ---
    def to_state_dict(self):
        return {
            "ema": self.ema,
            "emsd": self.emsd,
            "is_initialized": self.is_initialized,
            "consecutive_anomalies": self.consecutive_anomalies,
            "alpha": self.alpha,
            "threshold": self.threshold
        }

    def load_state_dict(self, data):
        self.ema = data.get("ema", 0.0)
        self.emsd = data.get("emsd", 1.0)
        self.is_initialized = data.get("is_initialized", False)
        self.consecutive_anomalies = data.get("consecutive_anomalies", 0)
        self.alpha = data.get("alpha", 0.2)
        self.threshold = data.get("threshold", 2.5)
    # -----------------------------

    def update(self, new_value):
        if not self.is_initialized:
            self.ema = new_value
            self.is_initialized = True
            return "TRAINING", False
        
        # Update EMA
        self.ema = self.alpha * new_value + (1 - self.alpha) * self.ema
        # Update EMSD
        diff = abs(new_value - self.ema)
        self.emsd = self.alpha * diff + (1 - self.alpha) * self.emsd
        
        if self.emsd == 0:
            self.emsd = 0.001
        z_score = (new_value - self.ema) / self.emsd
        
        # Decision Logic
        if z_score > self.threshold:
            self.consecutive_anomalies += 1
            if self.consecutive_anomalies >= self.required_failures:
                return "WARNING: Slow Response", True
            else:
                return "Unstable", False
        else:
            self.consecutive_anomalies = 0
            return "UP", False
# ============================================
# FIXED: MultiFeatureIsolationForest
# ============================================
class MultiFeatureIsolationForest:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.data = []           # CLEAN DATA ONLY
        self.all_data_count = 0  # Track total checks (including dirty)
        self.is_trained = False
        self.training_size = ISO_TRAINING_SIZE
        self.max_window = 200
        self.consecutive_anomalies = 0
        self.required_consecutive = 3
        self.first_clean_data_time = None  # Track when we started collecting clean data
        self.max_wait_seconds = 240        # Force train sooner so state does not stay untrained for long
        
    def to_state_dict(self):
        return {
            "is_trained": self.is_trained,
            "consecutive_anomalies": self.consecutive_anomalies,
            "required_consecutive": self.required_consecutive,
            "all_data_count": self.all_data_count,
            "first_clean_data_time": self.first_clean_data_time
        }

    def get_model_blob(self):
        return pickle.dumps(self.model)

    def load_model_blob(self, blob_data):
        self.model = pickle.loads(blob_data)
        self.is_trained = True

    def load_state_dict(self, data):
        self.consecutive_anomalies = data.get("consecutive_anomalies", 0)
        self.required_consecutive = data.get("required_consecutive", 3)
        self.all_data_count = data.get("all_data_count", 0)
        self.first_clean_data_time = data.get("first_clean_data_time", None)

    def _is_clean_sample(self, features: list) -> bool:
        """
        Validate that this data point is "clean" enough for training.
        Rejects: timeouts, errors, extreme outliers, zero values
        """
        latency = features[0]
        status_code = features[1]
        
        # Reject non-successful HTTP responses
        if status_code < 200 or status_code >= 400:
            return False
        
        # Reject zero or negative latency (indicates failed request)
        if latency <= 0:
            return False
        
        # Reject extreme outliers (> 10 seconds is likely an error, not real latency)
        if latency > 10000:
            return False
        
        return True

    def _should_force_train(self) -> bool:
        """
        Safety valve: If we've been collecting clean data for too long without
        meeting training requirements, force train to prevent deadlock.
        """
        if self.first_clean_data_time is None:
            return False
        
        elapsed = time.time() - self.first_clean_data_time
        return elapsed > self.max_wait_seconds

    def update(self, features: list, allow_learning=True):
        self.all_data_count += 1
        
        # ============================================
        # STEP 1: Clean data gate
        # ============================================
        is_clean = self._is_clean_sample(features)
        
        if is_clean:
            # Track when we started getting clean data
            if self.first_clean_data_time is None:
                self.first_clean_data_time = time.time()
            
            self.data.append(features)
            if len(self.data) > self.max_window:
                self.data.pop(0)
        else:
            # Dirty data - reset clean timer (environment might be unstable)
            self.first_clean_data_time = None
            # Don't add to training buffer, but still run detection if trained
            
        # ============================================
        # STEP 2: Detection (always run if trained)
        # ============================================
        if self.is_trained:
            try:
                prediction = self.model.predict([features])
                if prediction[0] == -1:
                    self.consecutive_anomalies += 1
                    if self.consecutive_anomalies >= self.required_consecutive:
                        return "ANOMALY: Multi-Feature Detected", True
                    else:
                        return "Unstable Pattern", False
                else:
                    self.consecutive_anomalies = 0
                    return "NORMAL", False
            except:
                return "ERROR", False
        
        # ============================================
        # STEP 3: Training logic (only if not trained)
        # ============================================
        if not self.is_trained:
            clean_count = len(self.data)
            
            if clean_count < self.training_size:
                return f"TRAINING: Collecting clean data ({clean_count}/{self.training_size})", False
            
            # We have enough clean data - check if we should train
            force_train = self._should_force_train()
            
            if allow_learning or force_train:
                try:
                    self.model.fit(self.data)
                    self.is_trained = True
                    mode = "forced" if force_train else "normal"
                    print(f"[ISOFOREST] {mode} training complete with {clean_count} clean samples")
                    return "TRAINED", False
                except Exception as e:
                    print(f"[ISOFOREST] Training error: {e}")
                    return "ERROR", False
            else:
                return "TRAINING: Waiting for stable environment", False
        
        return "TRAINING...", False


# ============================================
# FIXED: LSTMAutoencoderDetector  
# ============================================
class LSTMAutoencoderDetector:
    def __init__(self, target_name, timesteps=LSTM_TIMESTEPS, training_size=LSTM_TRAINING_SIZE, threshold_percentile=95.0):
        self.target_name = target_name.replace("/", "_").replace(":", "_")
        self.timesteps = timesteps
        self.training_size = max(training_size, timesteps + 10)
        self.threshold_percentile = threshold_percentile
        
        self.data = []           # CLEAN DATA ONLY
        self.all_data_count = 0  # Track total checks
        self.scaler = MinMaxScaler()
        self.model = None
        self.is_trained = False
        self.threshold = 0.0 
        self.consecutive_anomalies = 0
        self.required_consecutive = 2
        
        self.first_clean_data_time = None
        self.max_wait_seconds = 360  # Keep DL learning practical for many monitored targets

        self.load_model()

    def _create_model(self):
        model = Sequential([
            LSTM(64, activation='relu', input_shape=(self.timesteps, 1), return_sequences=True),
            Dropout(0.2),
            LSTM(32, activation='relu', return_sequences=False),
            Dropout(0.2),
            RepeatVector(self.timesteps),
            LSTM(32, activation='relu', return_sequences=True),
            LSTM(64, activation='relu', return_sequences=True),
            TimeDistributed(Dense(1))
        ])
        model.compile(optimizer='adam', loss='mae')
        return model

    def _create_sequences(self, values):
        output = []
        for i in range(len(values) - self.timesteps):
            output.append(values[i : (i + self.timesteps)])
        return np.expand_dims(output, axis=2)

    def _is_clean_sample(self, latency: float) -> bool:
        """
        Validate latency value is clean enough for training.
        """
        # Reject zero/negative (failed requests)
        if latency <= 0:
            return False
        
        # Reject extreme values (> 10 seconds)
        if latency > 10000:
            return False
        
        return True

    def _should_force_train(self) -> bool:
        """Safety valve to prevent infinite waiting"""
        if self.first_clean_data_time is None:
            return False
        elapsed = time.time() - self.first_clean_data_time
        return elapsed > self.max_wait_seconds

    def train(self):
        if len(self.data) < self.training_size:
            return "COLLECTING_DATA", False

        data_arr = np.array(self.data).reshape(-1, 1)
        self.scaler.fit(data_arr)
        scaled_data = self.scaler.transform(data_arr)
        X = self._create_sequences(scaled_data)
        if len(X) == 0:
            return "COLLECTING_DATA", False
        
        if self.model is None:
            self.model = self._create_model()

        self.model.fit(X, X, epochs=20, batch_size=32, validation_split=0.1, verbose=0,
                      callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, mode='min')])

        X_pred = self.model.predict(X, verbose=0)
        train_mae_loss = np.mean(np.abs(X_pred - X), axis=(1, 2))
        self.threshold = np.percentile(train_mae_loss, self.threshold_percentile)
        self.is_trained = True
        self.save_model()
        print(f"[LSTM] Training complete for {self.target_name}, threshold={self.threshold:.4f}")
        return "TRAINED", False

    def save_model(self):
        try:
            os.makedirs(SAVE_DIR, exist_ok=True)
            model_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}.h5")
            self.model.save(model_path)
            meta_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}_meta.pkl")
            joblib.dump({
                'threshold': self.threshold,
                'scaler': self.scaler,
                'data': self.data[-2000:]
            }, meta_path)
        except Exception as e:
            print(f"[ERROR] Failed to save model: {e}")

    def load_model(self):
        try:
            model_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}.h5")
            meta_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}_meta.pkl")
            
            if os.path.exists(model_path) and os.path.exists(meta_path):
                self.model = load_model(model_path)
                meta = joblib.load(meta_path)
                self.threshold = meta['threshold']
                self.scaler = meta['scaler']
                self.data = meta['data']
                self.is_trained = True
                print(f"[LSTM] Loaded existing model for {self.target_name}")
                return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
        return False

    def update(self, new_value, allow_learning=True):
        self.all_data_count += 1
        
        # ============================================
        # STEP 1: Clean data gate
        # ============================================
        is_clean = self._is_clean_sample(new_value)
        
        if is_clean:
            if self.first_clean_data_time is None:
                self.first_clean_data_time = time.time()
            
            self.data.append(new_value)
            if len(self.data) > 2000:
                self.data = self.data[-2000:]
        else:
            # Dirty data - reset clean timer
            self.first_clean_data_time = None
        
        # ============================================
        # STEP 2: Detection (always run if trained)
        # ============================================
        if self.is_trained:
            # For detection, we still need to check even dirty data
            if new_value <= 0:
                return "SKIPPED", False
                
            recent_data = np.array(self.data[-self.timesteps:]).reshape(-1, 1)
            if len(recent_data) < self.timesteps:
                return "RECOVERING: Buffering Data", False
                
            scaled_data = self.scaler.transform(recent_data)
            X_test = scaled_data.reshape(1, self.timesteps, 1)
            X_pred = self.model.predict(X_test, verbose=0)
            mae_loss = np.mean(np.abs(X_pred - X_test))
            
            if mae_loss > self.threshold * 2.0:
                self.consecutive_anomalies += 1
                if self.consecutive_anomalies >= self.required_consecutive:
                    return "CRITICAL: Pattern Breakdown (DL)", True
                else:
                    return "WARNING: Drifting...", False
            elif mae_loss > self.threshold:
                self.consecutive_anomalies += 1
                if self.consecutive_anomalies >= self.required_consecutive:
                    return "WARNING: High Reconstruction Error", True
                else:
                    return "Unstable", False
            else:
                self.consecutive_anomalies = 0
                return "OPERATIONAL", False
        
        # ============================================
        # STEP 3: Training logic (only if not trained)
        # ============================================
        if not self.is_trained:
            clean_count = len(self.data)
            
            if clean_count < self.training_size:
                return f"LEARNING: Collecting clean data ({clean_count}/{self.training_size})", False
            
            # Enough clean data - decide whether to train
            force_train = self._should_force_train()
            
            if allow_learning or force_train:
                status, _ = self.train()
                if status == "TRAINED":
                    return status, False
            else:
                return "LEARNING: Waiting for stable environment", False
        
        return "TRAINING...", False

# --- 4. MONITOR STATE ---
# Kept the complex state to maintain compatibility with your existing app structure
class MonitorState:
    def __init__(self):
        self.is_monitoring = False
        self.target_url: str = ""
        self.targets: List[str] = [] 
        self.passive_targets: List[str] = [] 
        self.probe_id = "PROBE-001" 
        
        # --- ADDED: Incident transition tracking ---
        self.previous_down_states: Dict[str, bool] = {}
        
        # Detectors
        self.detectors: Dict[str, SmartDetector] = {}
        self.lstm_detectors: Dict[str, LSTMAutoencoderDetector] = {}
        self.ml_detectors: Dict[str, MultiFeatureIsolationForest] = {}
        # History
        self.histories: Dict[str, List[float]] = {}
        self.timestamps: Dict[str, List[float]] = {}
        self.baseline_avgs: Dict[str, float] = {}
        self.current_statuses: Dict[str, str] = {}
        self.http_status_codes: Dict[str, int] = {}
        self.consecutive_probe_failures: Dict[str, int] = {}
        self.last_known_status: Dict[str, str] = {}
        self.last_known_latency: Dict[str, float] = {}

PROBE_FAILURE_THRESHOLD = 3
ACTIVE_HTTP_TIMEOUT = httpx.Timeout(connect=8.0, read=15.0, write=10.0, pool=8.0)
PASSIVE_HTTP_TIMEOUT = httpx.Timeout(connect=8.0, read=12.0, write=10.0, pool=8.0)

async def probe_target(client: httpx.AsyncClient, target: str, headers: Dict[str, str]):
    """
    Probe a target with HEAD first, then fall back to GET for servers/CDNs
    that reject or mishandle HEAD requests.
    """
    response = await client.head(target, headers=headers)

    # Some sites block HEAD or return a misleading non-healthy status even
    # though a normal GET request succeeds after redirects.
    if response.status_code in {301, 302, 303, 307, 308, 403, 405}:
        get_headers = dict(headers)
        get_headers["Range"] = "bytes=0-0"
        response = await client.get(target, headers=get_headers)

    return response

def classify_http_status(status_code: int) -> tuple[str, bool]:
    """
    Convert HTTP status codes into monitoring semantics.
    Returns (status_message, is_up).
    """
    if status_code >= 500:
        return f"SERVER DOWN ({status_code})", False

    if status_code in {401, 403}:
        return f"UP: Protected Resource ({status_code})", True

    if status_code == 404:
        return f"CLIENT ERROR ({status_code})", False

    if 400 <= status_code < 500:
        return f"CLIENT ERROR ({status_code})", False

    return "Operational", True

def register_probe_success(state: MonitorState, target: str, latency: float, status: str):
    state.consecutive_probe_failures[target] = 0
    state.last_known_status[target] = status
    state.last_known_latency[target] = latency

def classify_probe_exception(state: MonitorState, target: str, label: str) -> tuple[str, bool]:
    """
    A single failed probe should not immediately mark a healthy site as down.
    Only escalate after repeated consecutive failures.
    """
    failures = state.consecutive_probe_failures.get(target, 0) + 1
    state.consecutive_probe_failures[target] = failures

    if failures < PROBE_FAILURE_THRESHOLD:
        last_status = state.last_known_status.get(target, "Operational")
        return f"Intermittent Probe Issue ({label})", True if last_status else True

    return label, False

# --- 5. HYBRID MONITORING LOOP (WITH GUARDED LEARNING & INCIDENT TRACKING) ---
async def monitoring_loop(state: MonitorState):
    headers = {
        'User-Agent': 'Mozilla/5.0 (ServerPulse-AI/2.0; +https://serverpulse.ai)'
    }
    
    last_save_time = {} 

    while state.is_monitoring:
        for target in state.targets:
            current_latency = 0
            start_time = time.time() 
            
            # --- 1. INITIALIZATION PHASE ---
            if target not in state.detectors:
                saved_state = load_detector_state(target, "smart_detector")
                detector = SmartDetector()
                if saved_state and saved_state.parameters_json:
                    try:
                        data = json.loads(saved_state.parameters_json)
                        detector.load_state_dict(data)
                    except Exception as e: print(f"[WARN] Corrupt smart state: {e}")
                state.detectors[target] = detector
                if not saved_state:
                    save_detector_state(target, detector, "smart_detector")

            if target not in state.lstm_detectors:
                saved_lstm = load_detector_state(target, "lstm_metadata")
                lstm = LSTMAutoencoderDetector(target_name=target)
                if saved_lstm and saved_lstm.parameters_json:
                    try:
                        meta = json.loads(saved_lstm.parameters_json)
                        lstm.threshold = meta.get("threshold", 0.0)
                        lstm.is_trained = meta.get("is_trained", False)
                    except: pass
                state.lstm_detectors[target] = lstm
                if not saved_lstm:
                    save_detector_state(target, lstm, "lstm_metadata")

            if target not in state.ml_detectors:
                saved_iso = load_detector_state(target, "isolation_forest")
                iso = MultiFeatureIsolationForest()
                if saved_iso and saved_iso.model_blob:
                    try:
                        iso.load_model_blob(saved_iso.model_blob)
                        if saved_iso.parameters_json:
                            iso.load_state_dict(json.loads(saved_iso.parameters_json))
                    except: pass
                state.ml_detectors[target] = iso
                if not saved_iso:
                    save_detector_state(target, iso, "isolation_forest")

            if target not in last_save_time:
                last_save_time[target] = time.time()

            # --- 2. DATA COLLECTION & STABILITY CHECK ---
            try:
                async with httpx.AsyncClient(timeout=ACTIVE_HTTP_TIMEOUT, follow_redirects=True) as client:
                    response = await probe_target(client, target, headers)
                
                current_latency = (time.time() - start_time) * 1000
                state.http_status_codes[target] = response.status_code
                
                # --- 3. STABILITY GATEKEEPER ---
                # We run SmartDetector FIRST. If it says "ANOMALY", we block AI Learning.
                smart_status, smart_anomaly = state.detectors[target].update(current_latency)
                
                # If SmartDetector sees an anomaly, we do NOT allow AI to learn from this bad data.
                # However, AI can still DETECT the anomaly (we pass the data to update).
                allow_ai_learning = not smart_anomaly

                http_status, is_http_up = classify_http_status(response.status_code)

                # Critical HTTP errors bypass models
                if not is_http_up:
                    state.current_statuses[target] = http_status
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, response.status_code, 0, False)

                else:
                    # --- Run Isolation Forest ---
                    iso_features = [current_latency, response.status_code]
                    # Pass allow_ai_learning here
                    iso_status, iso_anomaly = state.ml_detectors[target].update(iso_features, allow_learning=allow_ai_learning)

                    # --- Run LSTM ---
                    # Pass allow_ai_learning here
                    lstm_status, lstm_anomaly = state.lstm_detectors[target].update(current_latency, allow_learning=allow_ai_learning)

                    # --- 4. HYBRID DECISION LOGIC ---
                    final_status = http_status
                    is_critical = False

                    # If AI is paused learning because of instability, report it
                    if not allow_ai_learning:
                        final_status = f"Stabilizing... ({smart_status})"
                        is_critical = smart_anomaly # Inherit critical state from SmartDetector
                    else:
                        # Normal Logic
                        if smart_anomaly:
                            final_status = f"WARNING: High Latency (SmartDet)"
                            is_critical = True
                        
                        if lstm_anomaly:
                            if "CRITICAL" in lstm_status:
                                final_status = f"CRITICAL: Pattern Breakdown (AI/LSTM)"
                                is_critical = True
                            elif "WARNING" in lstm_status:
                                if not is_critical:
                                    final_status = f"WARNING: Trend Anomaly (AI/LSTM)"
                        
                        if iso_anomaly:
                            if not is_critical:
                                final_status = "WARNING: Complex Anomaly (IsoForest)"

                        if "TRAINING" in smart_status or "LEARNING" in lstm_status:
                            final_status = "Learning System Behavior..."
                    
                    state.current_statuses[target] = final_status
                    update_history(state, target, current_latency)
                    save_monitor_log_entry(target, response.status_code, current_latency, True)
                    register_probe_success(state, target, current_latency, final_status)

                    # Persist trained state immediately instead of waiting for the next
                    # periodic checkpoint so monitor_model_states reflects reality.
                    if iso_status == "TRAINED":
                        save_detector_state(target, state.ml_detectors[target], "isolation_forest")
                    if lstm_status == "TRAINED":
                        save_detector_state(target, state.lstm_detectors[target], "lstm_metadata")
                    
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as e:
                timeout_status, is_timeout_up = classify_probe_exception(state, target, "WARNING: Connection Timeout")
                state.current_statuses[target] = timeout_status
                if is_timeout_up:
                    update_history(state, target, state.last_known_latency.get(target, 0))
                    save_monitor_log_entry(target, None, state.last_known_latency.get(target, 0), True)
                else:
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, None, 0, False)
            except httpx.ConnectError:
                error_status, is_error_up = classify_probe_exception(state, target, "CONNECTION REFUSED")
                state.current_statuses[target] = error_status
                if is_error_up:
                    update_history(state, target, state.last_known_latency.get(target, 0))
                    save_monitor_log_entry(target, None, state.last_known_latency.get(target, 0), True)
                else:
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, None, 0, False)
            except Exception as e:
                error_status, is_error_up = classify_probe_exception(state, target, f"ERROR: {str(e)[:20]}")
                state.current_statuses[target] = error_status
                if is_error_up:
                    update_history(state, target, state.last_known_latency.get(target, 0))
                    save_monitor_log_entry(target, None, state.last_known_latency.get(target, 0), True)
                else:
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, None, 0, False)

            # --- 5. ALERTS ---
            check_service_alerts(target, state.current_statuses.get(target, "Unknown"), current_latency)

            # --- 6. PERSISTENCE ---
            if time.time() - last_save_time.get(target, 0) > 60:
                save_detector_state(target, state.detectors[target], "smart_detector")
                save_detector_state(target, state.ml_detectors[target], "isolation_forest")
                save_detector_state(target, state.lstm_detectors[target], "lstm_metadata")
                last_save_time[target] = time.time()

            # ============================================================
            # --- 7. INCIDENT TRACKING (NEW) ---
            # ============================================================
            status_str = state.current_statuses.get(target, "").upper()
            is_currently_down = (
                "DOWN" in status_str or
                "ERROR" in status_str or
                "REFUSED" in status_str or
                ("TIMEOUT" in status_str and "INTERMITTENT" not in status_str) or
                "CRITICAL" in status_str or
                "NOT FOUND" in status_str
            )
            
            # Check previous state (default to UP if not tracked yet)
            was_previously_down = state.previous_down_states.get(target, False)
            
            # Detect STATE TRANSITION
            if is_currently_down and not was_previously_down:
                # UP → DOWN transition: OPEN new incident
                handle_incident_tracking(target, state.current_statuses.get(target, ""), True)
            elif not is_currently_down and was_previously_down:
                # DOWN → UP transition: RESOLVE existing incident
                handle_incident_tracking(target, state.current_statuses.get(target, ""), False)
            
            # Update previous state for next iteration
            state.previous_down_states[target] = is_currently_down
            # ============================================================

        await asyncio.sleep(1.5) 

# --- PASSIVE MONITORING LOOP (REPLACED WITH SNIPPET LOGIC) ---
async def passive_monitoring_loop(state: MonitorState):
    headers = {
        'User-Agent': 'Mozilla/5.0 (ServerPulse-AI/Passive-Scan/1.0; +https://serverpulse.ai)'
    }
    
    PASSIVE_SCAN_INTERVAL = 60 
    
    while state.is_monitoring:
        if not state.passive_targets:
            await asyncio.sleep(PASSIVE_SCAN_INTERVAL)
            continue

        for target in state.passive_targets:
            current_latency = 0
            start_time = time.time() 
            current_status = "Unknown"
            
            try:
                async with httpx.AsyncClient(timeout=PASSIVE_HTTP_TIMEOUT, follow_redirects=True) as client:
                    response = await probe_target(client, target, headers)
                    
                current_latency = (time.time() - start_time) * 1000
                current_status, _ = classify_http_status(response.status_code)
                register_probe_success(state, target, current_latency, current_status)
                    
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
                current_status, _ = classify_probe_exception(state, target, "WARNING: Connection Timeout")
            except httpx.ConnectError:
                current_status, _ = classify_probe_exception(state, target, "CONNECTION REFUSED")
            except Exception as e:
                current_status, _ = classify_probe_exception(state, target, f"ERROR: {str(e)[:20]}")

            check_service_alerts(target, current_status, current_latency)
            
        await asyncio.sleep(PASSIVE_SCAN_INTERVAL)

# --- UPDATE HISTORY (FIXED FROM SNIPPET) ---
def update_history(state: MonitorState, target: str, val: float):
    if target not in state.histories:
        state.histories[target] = []
        state.timestamps[target] = []
    
    # NOTE: Corrected 'self' to 'state' which was in your snippet
    state.histories[target].append(val)
    state.timestamps[target].append(time.time())
    
    if target in state.detectors:
        state.baseline_avgs[target] = state.detectors[target].ema
    
    if len(state.histories[target]) > 50:
        state.histories[target].pop(0)
        state.timestamps[target].pop(0)
