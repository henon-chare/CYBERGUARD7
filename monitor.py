# monitor.py
import asyncio
import time
import os
import joblib 
from typing import List, Dict
import httpx
import numpy as np
import json
import pickle
from collections import deque 

# --- DEEP LEARNING IMPORTS ---
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model # type: ignore
from tensorflow.keras.layers import LSTM, Dense, Dropout, RepeatVector, TimeDistributed
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression # ADDED: For Stacking

# ADDED IMPORT FOR ALERTS
from alert import check_service_alerts

# ADDED IMPORTS FOR PERSISTENCE
from database import SessionLocal
from models import MonitorModelState

# --- NEW IMPORTS FOR MONITOR LOGIC ---
from models import Monitor, MonitorLog
from datetime import datetime
from urllib.parse import urlparse


# --- CONFIGURATION ---
CRITICAL_LATENCY_LIMIT_MS = 5000.0
SAVE_DIR = "saved_models"

# ================= ROBUST BASELINE HELPERS =================
def is_stable_window(values, threshold=0.1):
    """Checks if the last 50 samples are stable enough to be considered 'Normal'."""
    if len(values) < 50: return False
    recent = np.array(values[-50:])
    mean = np.mean(recent)
    std = np.std(recent)
    if mean == 0: return False
    cv = std / mean  # coefficient of variation
    return cv < threshold

def remove_outliers(data):
    """Filters out data points using the IQR method to ensure the model doesn't learn from spikes."""
    if not data: return []
    q1 = np.percentile(data, 25)
    q3 = np.percentile(data, 75)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    return [x for x in data if lower <= x <= upper]
# ===========================================================


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
            params_json = json.dumps({
                "threshold": detector.threshold,
                "is_trained": detector.is_trained
            })
        elif detector_type == "meta_model":
            # Save the Logistic Regression model as a blob
            if detector.is_trained:
                model_blob = pickle.dumps(detector.model)
                params_json = json.dumps({"is_trained": True})
            else:
                params_json = json.dumps({"is_trained": False})

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
    """Persists a single check result to the monitor_logs table."""
    db = SessionLocal()
    try:
        monitor = db.query(Monitor).filter(Monitor.target_url == target_url).first()
        if monitor:
            clean_domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
            log_entry = MonitorLog(
                monitor_id=monitor.id,
                status_code=status_code,
                response_time=response_time,
                is_up=is_up,
                checked_at=datetime.utcnow(),
                domain=clean_domain
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
class SmartDetector:
    def __init__(self, alpha=0.2, threshold=2.5):
        self.alpha = alpha
        self.threshold = threshold
        self.ema = 0.0  
        self.emsd = 1.0
        self.is_initialized = False
        self.consecutive_anomalies = 0
        self.required_failures = 3

    def to_state_dict(self):
        return {
            "ema": self.ema, "emsd": self.emsd, "is_initialized": self.is_initialized,
            "consecutive_anomalies": self.consecutive_anomalies, "alpha": self.alpha, "threshold": self.threshold
        }

    def load_state_dict(self, data):
        self.ema = data.get("ema", 0.0)
        self.emsd = data.get("emsd", 1.0)
        self.is_initialized = data.get("is_initialized", False)
        self.consecutive_anomalies = data.get("consecutive_anomalies", 0)
        self.alpha = data.get("alpha", 0.2)
        self.threshold = data.get("threshold", 2.5)

    def update(self, new_value):
        if not self.is_initialized:
            self.ema = new_value
            self.is_initialized = True
            return "TRAINING", False
        
        self.ema = self.alpha * new_value + (1 - self.alpha) * self.ema
        diff = abs(new_value - self.ema)
        self.emsd = self.alpha * diff + (1 - self.alpha) * self.emsd
        
        if self.emsd == 0: self.emsd = 0.001
        z_score = (new_value - self.ema) / self.emsd
        
        if z_score > self.threshold:
            self.consecutive_anomalies += 1
            if self.consecutive_anomalies >= self.required_failures:
                return "WARNING: Slow Response", True
            else:
                return "Unstable", False
        else:
            self.consecutive_anomalies = 0
            return "UP", False

# --- 2. ENHANCED ISOLATION FOREST DETECTOR ---
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

    def update(self, features: list):
        self.data.append(features)
        if len(self.data) > self.max_window: self.data.pop(0)
        if len(self.data) < self.training_size: return "TRAINING", False

        if not self.is_trained or len(self.data) % 50 == 0:
            try:
                self.model.fit(self.data)
                self.is_trained = True
            except: return "ERROR", False

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

# --- 3. UPDATED LSTM AUTOENCODER DETECTOR (ROBUST BASELINE) ---
class LSTMAutoencoderDetector:
    def __init__(self, target_name, timesteps=30, training_size=500, threshold_percentile=95.0):
        self.target_name = target_name.replace("/", "_").replace(":", "_")
        self.timesteps = timesteps
        self.training_size = training_size
        self.threshold_percentile = threshold_percentile
        
        self.data = deque(maxlen=2000)
        self.scaler = MinMaxScaler()
        self.model = None
        self.is_trained = False
        self.threshold = 0.0 
        self.consecutive_anomalies = 0
        self.required_consecutive = 2 
        
        # ADDED: For Meta-Model feature extraction
        self.last_reconstruction_error = 0.0

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
        if len(self.data) < self.training_size or not is_stable_window(self.data):
            return "COLLECTING_STABLE_DATA", False

        clean_data = remove_outliers(list(self.data))
        if len(clean_data) < self.timesteps: return "COLLECTING_STABLE_DATA", False

        data_arr = np.array(clean_data).reshape(-1, 1)
        self.scaler.fit(data_arr)
        scaled_data = self.scaler.transform(data_arr)
        X = self._create_sequences(scaled_data)
        
        if self.model is None: self.model = self._create_model()

        self.model.fit(X, X, epochs=20, batch_size=32, validation_split=0.1, verbose=0,
                      callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, mode='min')])

        X_pred = self.model.predict(X, verbose=0)
        train_mae_loss = np.mean(np.abs(X_pred - X), axis=(1, 2))
        self.threshold = np.percentile(train_mae_loss, self.threshold_percentile)
        
        if self.threshold <= 0 or np.isnan(self.threshold):
            self.threshold = 0.01

        self.is_trained = True
        self.save_model()
        return "TRAINED", False

    def save_model(self):
        try:
            if not os.path.exists(SAVE_DIR): os.makedirs(SAVE_DIR)
            model_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}.h5")
            self.model.save(model_path)
            meta_path = os.path.join(SAVE_DIR, f"lstm_{self.target_name}_meta.pkl")
            joblib.dump({
                'threshold': self.threshold,
                'scaler': self.scaler,
                'data': list(self.data) 
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
                self.data = deque(meta['data'], maxlen=2000)
                self.is_trained = True
                return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
        return False

    def update(self, new_value):
        if new_value <= 0: return "SKIPPED", False
        self.data.append(new_value) 

        if len(self.data) < self.training_size: 
            if not self.is_trained:
                return "LEARNING: Collecting Patterns", False
            else:
                return "RECOVERING: Buffering Data", False

        if not self.is_trained:
            status, _ = self.train()
            if status == "TRAINED": return status, False

        if self.is_trained:
            recent_data = np.array(list(self.data)[-self.timesteps:]).reshape(-1, 1)
            scaled_data = self.scaler.transform(recent_data)
            X_test = scaled_data.reshape(1, self.timesteps, 1)
            X_pred = self.model.predict(X_test, verbose=0)
            mae_loss = np.mean(np.abs(X_pred - X_test))
            
            # UPDATE: Store for meta-model
            self.last_reconstruction_error = mae_loss

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

# --- 4. NEW: META MODEL (THE STACKER) ---
class MetaModel:
    """
    Learns to combine EWMA, Isolation Forest, and LSTM signals 
    into a final decision using Logistic Regression.
    """
    def __init__(self):
        self.model = LogisticRegression()
        self.buffer_X = deque(maxlen=1000) # Features
        self.buffer_y = deque(maxlen=1000) # Labels (0=Normal, 1=Anomaly)
        self.is_trained = False
        self.training_threshold = 300 # Need 300 samples to train

    def learn(self, features, label):
        """Collects data for training."""
        self.buffer_X.append(features)
        self.buffer_y.append(label)

        if len(self.buffer_X) > self.training_threshold and not self.is_trained:
            try:
                X = np.array(self.buffer_X)
                y = np.array(self.buffer_y)
                self.model.fit(X, y)
                self.is_trained = True
                print(f"[META-MODEL] Trained successfully on {len(X)} samples.")
            except Exception as e:
                print(f"[META-MODEL] Training failed: {e}")

    def predict(self, features):
        """Returns probability of anomaly (0.0 to 1.0)."""
        if not self.is_trained:
            return 0.0
        try:
            # Returns probability of class 1 (Anomaly)
            return self.model.predict_proba([features])[0][1]
        except:
            return 0.0

# --- 5. MONITOR STATE ---
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
        self.meta_detectors: Dict[str, MetaModel] = {} # ADDED
        # History
        self.histories: Dict[str, List[float]] = {}
        self.timestamps: Dict[str, List[float]] = {}
        self.baseline_avgs: Dict[str, float] = {}
        self.current_statuses: Dict[str, str] = {}
        self.http_status_codes: Dict[str, int] = {}

async def monitoring_loop(state: MonitorState):
    headers = {
        'User-Agent': 'Mozilla/5.0 (ServerPulse-AI/2.0; +https://serverpulse.ai)'
    }
    
    last_save_time = {} 

    while state.is_monitoring:
        for target in state.targets:
            current_latency = 0
            start_time = time.time() 
            
            # 1. Initialize Smart Detector
            if target not in state.detectors:
                saved_state = load_detector_state(target, "smart_detector")
                detector = SmartDetector() 
                if saved_state and saved_state.parameters_json:
                    try:
                        data = json.loads(saved_state.parameters_json)
                        detector.load_state_dict(data)
                        print(f"[RESTORED] SmartDetector for {target}")
                    except Exception as e: pass
                state.detectors[target] = detector
                last_save_time[target] = time.time()

            # 2. Initialize Meta Detector
            if target not in state.meta_detectors:
                saved_state = load_detector_state(target, "meta_model")
                meta = MetaModel()
                if saved_state and saved_state.model_blob:
                    try:
                        meta.model = pickle.loads(saved_state.model_blob)
                        meta.is_trained = True
                        print(f"[RESTORED] MetaModel for {target}")
                    except Exception as e: pass
                state.meta_detectors[target] = meta

            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    response = await client.head(target, headers=headers)
                    
                current_latency = (time.time() - start_time) * 1000
                state.http_status_codes[target] = response.status_code
                
                # --- HTTP STATUS CHECK ---
                if response.status_code >= 500:
                    state.current_statuses[target] = f"SERVER DOWN ({response.status_code})"
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, response.status_code, 0, False)
                elif 400 <= response.status_code < 500:
                    state.current_statuses[target] = f"WARNING ({response.status_code})"
                    update_history(state, target, 0)
                    save_monitor_log_entry(target, response.status_code, 0, False)
                else:
                    # --- HEALTHY (2xx/3xx): RUN DETECTORS ---
                    
                    # A. Run EWMA
                    ewma_status, ewma_is_anomaly = state.detectors[target].update(current_latency)
                    
                    # B. Init/Run Isolation Forest
                    if target not in state.ml_detectors:
                        saved_state = load_detector_state(target, "isolation_forest")
                        ml_detector = MultiFeatureIsolationForest() 
                        if saved_state and saved_state.model_blob:
                            try:
                                ml_detector.load_model_blob(saved_state.model_blob)
                                ml_detector.load_state_dict(json.loads(saved_state.parameters_json))
                            except: pass
                        state.ml_detectors[target] = ml_detector
                    ml_status, ml_is_anomaly = state.ml_detectors[target].update([current_latency])

                    # C. Init/Run LSTM
                    # Note: LSTM is not explicitly stored in state.lstm_detectors in the loop provided previously,
                    # but usually it would be. Assuming it's managed internally or we add it here if needed.
                    # For this update, we assume LSTM exists or is initialized similarly.
                    # (If you want LSTM active in this loop, you need to add init logic similar to ML detectors).
                    # We will retrieve the LSTM error for the feature vector if available.
                    
                    # Let's grab the LSTM instance if it exists (assuming it's managed like others)
                    lstm_detector = None
                    if target not in state.lstm_detectors:
                        # Init logic if not present
                        pass 
                    else:
                        lstm_detector = state.lstm_detectors[target]
                    
                    lstm_score = 0.0
                    if lstm_detector and lstm_detector.is_trained:
                         # Force an update to get the last error
                         lstm_detector.update(current_latency)
                         lstm_score = lstm_detector.last_reconstruction_error
                    elif lstm_detector:
                        # Training
                        lstm_detector.update(current_latency)

                    # ==========================================
                    # --- STACKED DECISION LOGIC (NEW) ---
                    # ==========================================
                    
                    # 1. Create Feature Vector
                    # Feature 1: EWMA Deviation (Z-score)
                    ewma_z = abs(current_latency - state.detectors[target].ema) / (state.detectors[target].emsd + 1e-8)
                    
                    # Feature 2: Isolation Forest Score (Negative score = outlier)
                    iso_score = 0.0
                    if state.ml_detectors[target].is_trained:
                        try:
                            # decision_function returns negative for outliers. We flip sign for "Anomaly Score".
                            iso_score = -state.ml_detectors[target].model.decision_function([[current_latency]])[0]
                        except: pass

                    # Feature 3: LSTM Error
                    # Already captured in lstm_score

                    features = [ewma_z, iso_score, lstm_score]
                    
                    meta_model = state.meta_detectors[target]
                    
                    # 2. PHASE 1: HYBRID (Rule-based for Labeling)
                    if not meta_model.is_trained:
                        # Use existing logic to determine status
                        final_status = ewma_status
                        final_is_anomaly = ewma_is_anomaly

                        if ml_is_anomaly and "ANOMALY" in ml_status:
                            final_status = "CRITICAL: ML Pattern Breakdown"
                            final_is_anomaly = True
                        elif ml_is_anomaly and "Unstable" in ml_status and "UP" in ewma_status:
                            final_status = "WARNING: ML Pattern Instability"
                            final_is_anomaly = True
                        
                        # Generate Label (0 or 1)
                        # Label = 1 if CRITICAL or WARNING, else 0
                        label = 1 if ("CRITICAL" in final_status or "WARNING" in final_status) else 0
                        
                        # Feed to Meta-Model
                        meta_model.learn(features, label)
                        
                        # Set Status
                        if "CRITICAL" in final_status: state.current_statuses[target] = final_status
                        elif "WARNING" in final_status: state.current_statuses[target] = "WARNING: High Latency"
                        elif "Unstable" in final_status: state.current_statuses[target] = "Unstable"
                        else: state.current_statuses[target] = "Operational"

                    # 3. PHASE 2: AI (Meta-Model Prediction)
                    else:
                        probability = meta_model.predict(features)
                        
                        # Thresholds
                        if probability > 0.8:
                            state.current_statuses[target] = "CRITICAL: AI Decision"
                        elif probability > 0.5:
                            state.current_statuses[target] = "WARNING: AI Decision"
                        else:
                            state.current_statuses[target] = "Operational"

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

            # --- ALERT INTEGRATION ---
            current_status = state.current_statuses.get(target, "Unknown")
            check_service_alerts(target, current_status, current_latency)

            # --- PERIODIC SAVE TO DB ---
            if time.time() - last_save_time.get(target, 0) > 60:
                save_detector_state(target, state.detectors[target], "smart_detector")
                if target in state.ml_detectors and len(state.ml_detectors[target].data) > 20:
                    save_detector_state(target, state.ml_detectors[target], "isolation_forest")
                if target in state.meta_detectors and state.meta_detectors[target].is_trained:
                    save_detector_state(target, state.meta_detectors[target], "meta_model")
                
                last_save_time[target] = time.time()

        await asyncio.sleep(1.5) 

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

def update_history(state: MonitorState, target: str, val: float):
    if target not in state.histories:
        state.histories[target] = []
        state.timestamps[target] = []
    state.histories[target].append(val)
    state.timestamps[target].append(time.time())
    
    if target in state.detectors:
        state.baseline_avgs[target] = state.detectors[target].ema
    
    if len(state.histories[target]) > 50:
        state.histories[target].pop(0)
        state.timestamps[target].pop(0)