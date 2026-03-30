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
from models import Monitor, MonitorLog
from datetime import datetime
from urllib.parse import urlparse # ADDED IMPORT


# --- CONFIGURATION ---
CRITICAL_LATENCY_LIMIT_MS = 5000.0
SAVE_DIR = "saved_models"

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
            # 2. Extract the domain from the target_url for the new column
            # This strips 'http://' or 'https://' and removes any paths (e.g., /login)
            clean_domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]

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
# =======================================================


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

class MultiFeatureIsolationForest:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.data = []
        self.is_trained = False
        self.training_size = 100 
        self.max_window = 200
        self.consecutive_anomalies = 0
        self.required_consecutive = 3 
        
    def to_state_dict(self):
        return {
            "is_trained": self.is_trained,
            "consecutive_anomalies": self.consecutive_anomalies,
            "required_consecutive": self.required_consecutive
        }

    def get_model_blob(self):
        return pickle.dumps(self.model)

    def load_model_blob(self, blob_data):
        self.model = pickle.loads(blob_data)
        self.is_trained = True

    def load_state_dict(self, data):
        self.consecutive_anomalies = data.get("consecutive_anomalies", 0)
        self.required_consecutive = data.get("required_consecutive", 3)

    def update(self, features: list, allow_learning=True): # <--- MODIFIED SIGNATURE
        self.data.append(features)
        if len(self.data) > self.max_window: self.data.pop(0)
        if len(self.data) < self.training_size: return "TRAINING", False

        # --- GUARDED TRAINING LOGIC ---
        # Only retrain periodically AND if system is stable
        should_train = (not self.is_trained) or (len(self.data) % 50 == 0)
        
        if should_train:
            if allow_learning:
                try:
                    self.model.fit(self.data)
                    self.is_trained = True
                except: return "ERROR", False
            else:
                # Skip training to avoid learning bad patterns, but keep data in window
                return "PAUSED LEARNING: Unstable", False

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

class LSTMAutoencoderDetector:
    def __init__(self, target_name, timesteps=30, training_size=500, threshold_percentile=95.0):
        self.target_name = target_name.replace("/", "_").replace(":", "_")
        self.timesteps = timesteps
        self.training_size = training_size
        self.threshold_percentile = threshold_percentile
        
        self.data = []
        self.scaler = MinMaxScaler()
        self.model = None
        self.is_trained = False
        self.threshold = 0.0 
        self.consecutive_anomalies = 0
        self.required_consecutive = 2 

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

    def train(self):
        if len(self.data) < self.training_size: return "COLLECTING_DATA", False

        data_arr = np.array(self.data).reshape(-1, 1)
        self.scaler.fit(data_arr)
        scaled_data = self.scaler.transform(data_arr)
        X = self._create_sequences(scaled_data)
        if self.model is None: self.model = self._create_model()

        self.model.fit(X, X, epochs=20, batch_size=32, validation_split=0.1, verbose=0,
                      callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, mode='min')])

        X_pred = self.model.predict(X, verbose=0)
        train_mae_loss = np.mean(np.abs(X_pred - X), axis=(1, 2))
        self.threshold = np.percentile(train_mae_loss, self.threshold_percentile)
        self.is_trained = True
        self.save_model()
        return "TRAINED", False

    def save_model(self):
        try:
            if not os.path.exists(SAVE_DIR):
                os.makedirs(SAVE_DIR)
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
                return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False
        return False

    def update(self, new_value, allow_learning=True): # <--- MODIFIED SIGNATURE
        if new_value <= 0: return "SKIPPED", False
        self.data.append(new_value)
        if len(self.data) > 2000: self.data = self.data[-2000:]

        if len(self.data) < self.training_size: 
            if not self.is_trained:
                # Only collect data, don't train yet
                return "LEARNING: Collecting Patterns", False
            else:
                return "RECOVERING: Buffering Data", False

        # --- GUARDED TRAINING LOGIC ---
        if not self.is_trained:
            # Only train if allowed (i.e., SmartDetector says system is stable)
            if allow_learning:
                status, _ = self.train()
                if status == "TRAINED": return status, False
            else:
                return "PAUSED LEARNING: Unstable Environment", False

        if self.is_trained:
            recent_data = np.array(self.data[-self.timesteps:]).reshape(-1, 1)
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

# --- 5. HYBRID MONITORING LOOP (WITH GUARDED LEARNING) ---
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

            if target not in last_save_time:
                last_save_time[target] = time.time()

            # --- 2. DATA COLLECTION & STABILITY CHECK ---
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    response = await client.head(target, headers=headers)
                
                current_latency = (time.time() - start_time) * 1000
                state.http_status_codes[target] = response.status_code
                
                # --- 3. STABILITY GATEKEEPER ---
                # We run SmartDetector FIRST. If it says "ANOMALY", we block AI Learning.
                smart_status, smart_anomaly = state.detectors[target].update(current_latency)
                
                # If SmartDetector sees an anomaly, we do NOT allow AI to learn from this bad data.
                # However, AI can still DETECT the anomaly (we pass the data to update).
                allow_ai_learning = not smart_anomaly

                # Critical HTTP Errors bypass models
                if response.status_code >= 500:
                    state.current_statuses[target] = f"SERVER DOWN ({response.status_code})"
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, response.status_code, 0, False)
                
                elif 400 <= response.status_code < 500:
                    state.current_statuses[target] = f"CLIENT ERROR ({response.status_code})"
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
                    final_status = "Operational"
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
                    
            except httpx.ConnectTimeout:
                state.current_statuses[target] = "WARNING: Connection Timeout"
                update_history(state, target, 0)
                save_monitor_log_entry(target, None, 0, False) 
            except httpx.ConnectError:
                state.current_statuses[target] = "CONNECTION REFUSED"
                update_history(state, target, 0)
                save_monitor_log_entry(target, None, 0, False)
            except Exception as e:
                state.current_statuses[target] = f"ERROR: {str(e)[:20]}"
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
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                    response = await client.head(target, headers=headers)
                    
                current_latency = (time.time() - start_time) * 1000
                
                if response.status_code >= 500:
                    current_status = f"SERVER DOWN ({response.status_code})"
                elif 400 <= response.status_code < 500:
                    current_status = f"ERROR ({response.status_code})"
                else:
                    current_status = "Operational"
                    
            except httpx.ConnectTimeout:
                current_status = "WARNING: Connection Timeout"
            except httpx.ConnectError:
                current_status = "CONNECTION REFUSED"
            except Exception as e:
                current_status = f"ERROR: {str(e)[:20]}"

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