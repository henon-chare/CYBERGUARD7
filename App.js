import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import "./App.css";

// ================= HELPER FUNCTIONS =================
const formatDate = (dateStr) => {
  if (!dateStr) return "Unknown";
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return "Invalid Date";
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch (e) {
    return "Unknown";
  }
};

const formatDateTime = (dateStr) => {
  if (!dateStr) return "-";
  try {
    const date = new Date(dateStr);
    return date.toLocaleString();
  } catch (e) { return dateStr; }
};

// PASSWORD VALIDATION HELPER (Mirrors Backend)
const validateReportPassword = (password, username) => {
  if (!password) return { valid: false, msg: "Password cannot be empty." };
  if (password.length < 8) return { valid: false, msg: "Password too short (min 8 chars)." };
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    return { valid: false, msg: "Password too similar to username." };
  }
  if (!/[A-Z]/.test(password)) return { valid: false, msg: "Password must contain uppercase." };
  if (!/[a-z]/.test(password)) return { valid: false, msg: "Password must contain lowercase." };
  if (!/\d/.test(password)) return { valid: false, msg: "Password must contain a number." };
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return { valid: false, msg: "Password must contain a special character." };
  return { valid: true, msg: "" };
};

// ================= RISK SCORING ALGORITHM (UPDATED - NO SSL) =================
// ================= RISK SCORING ALGORITHM (UPDATED - NEW CHECKLISTS) =================
const calculateRisk = (manualData) => {
  let score = 0;
  let riskLevel = "Low";
  let color = "var(--status-green)";

  // --- 1. EXISTING LOGIC: Expiration & Lifecycle ---
  const expDate = new Date(manualData.expirationDate || manualData.apiExpiration);
  const now = new Date();
  
  // Handle invalid dates gracefully
  if (isNaN(expDate.getTime())) {
      // If date is invalid, assume high risk
      score += 40;
  } else {
      const daysLeft = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));

      if (daysLeft < 0) {
        score += 80;
      } else if (daysLeft < 30) {
        score += 50;
      } else if (daysLeft < 90) {
        score += 20;
      }
  }

  if (!manualData.autoRenew) {
    score += 30; 
  }

  if (manualData.purpose === "production") {
    score += 10;
  }

  // --- 2. NEW LOGIC: Security Checklists Integration ---
  const s = manualData.security || {};

  // We REDUCE the score (Lower Risk) when these security measures are active (Checked).
  
  // 🔐 Registrar Security (Weight: -5 each)
  if (s.mfa) score -= 5;
  if (s.lock) score -= 5;
  if (s.registrarLock) score -= 5;
  if (s.registryLock) score -= 5;

  // 🌐 DNS Security (Weight: -5 each)
  if (s.dnssec) score -= 5;
  if (s.secureNameservers) score -= 5;
  if (s.noDanglingRecords) score -= 5;

  // 🔑 Web Security (Weight: -5 each)
  if (s.tlsVersion) score -= 5;
  if (s.sslExpiry) score -= 5;
  if (s.hsts) score -= 5;

  // 📧 Email Security (Weight: -5 each)
  if (s.spf) score -= 5;
  if (s.dkim) score -= 5;
  if (s.dmarc) score -= 5;

  // 🛡️ Threat Monitoring (Weight: -10 each, High Value)
  if (s.blacklistCheck) score -= 10;
  if (s.phishingDetection) score -= 10;
  if (s.typosquatting) score -= 10;

  // --- 3. FINAL CALCULATION ---
  // Ensure score stays between 0 and 100
  score = Math.max(0, Math.min(100, score));

  if (score >= 60) {
    riskLevel = "Critical";
    color = "var(--status-red)";
  } else if (score >= 30) {
    riskLevel = "Medium";
    color = "var(--status-orange)";
  } else {
    riskLevel = "Low";
    color = "var(--status-green)";
  }

  return { score, riskLevel, color };
};

// ================= DOMAIN ADD MODAL (NEW) =================
const DomainAddModal = ({ isOpen, onClose, onAdd, isLoading }) => {
  const [domain, setDomain] = useState("");

  useEffect(() => {
    if (isOpen) {
      setDomain(""); // Reset input when modal opens
    }
  }, [isOpen]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (domain.trim()) {
      onAdd(domain.trim());
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>Track New Domain</h3>
        <p style={{color: 'var(--text-muted)', marginBottom: '20px', fontSize: '0.9rem'}}>
          Enter the domain name you wish to monitor for DNS, WHOIS, and Expiration changes.
        </p>
        
        <form onSubmit={handleSubmit} style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
          <div>
            <label className="form-label">DOMAIN NAME</label>
            <input 
              type="text" 
              className="cyber-input" 
              placeholder="e.g. mycompany.com" 
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              autoFocus
              disabled={isLoading}
              autoComplete="off"
            />
          </div>

          <div className="modal-actions">
            <button type="button" onClick={onClose} className="btn-cancel" disabled={isLoading}>
              Cancel
            </button>
            <button type="submit" className="btn-submit" disabled={isLoading || !domain.trim()}>
              {isLoading ? "Tracking..." : "Track Domain"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ================= CONFIRM MODAL COMPONENT =================
const ConfirmModal = ({ isOpen, onClose, onConfirm, title, message }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>{title || "Confirm Action"}</h3>
        <p style={{color: 'var(--text-muted)', marginBottom: '20px', fontSize: '0.9rem', lineHeight: '1.5'}}>
          {message || "Are you sure you want to proceed?"}
        </p>
        <div className="modal-actions">
          <button onClick={onClose} className="btn-cancel">Cancel</button>
          <button onClick={onConfirm} className="btn-modal-danger">Confirm</button>
        </div>
      </div>
    </div>
  );
};

// ================= PASSWORD MODAL COMPONENT =================
const PasswordModal = ({ isOpen, onClose, onSubmit, title, username }) => {
  const [pwd, setPwd] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    if (errorMsg) setErrorMsg("");
  }, [pwd, confirm, errorMsg]);

  if (!isOpen) return null;

  const handleSubmit = () => {
    if (pwd !== confirm) {
      setErrorMsg("Passwords do not match!");
      return;
    }

    const strengthCheck = validateReportPassword(pwd, username);
    if (!strengthCheck.valid) {
      setErrorMsg(strengthCheck.msg);
      return;
    }

    onSubmit(pwd);
    setPwd("");
    setConfirm("");
    setErrorMsg("");
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>{title || "Secure PDF Report"}</h3>
        <p style={{fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "15px"}}>
          Enter a strong password to encrypt the PDF.
        </p>
        
        {errorMsg && (
          <div className="modal-error">
            ⚠️ {errorMsg}
          </div>
        )}

        <div className="modal-input-group">
          <input 
            type="password" 
            placeholder="Enter Password" 
            value={pwd} 
            onChange={(e) => setPwd(e.target.value)} 
            autoFocus
            className={errorMsg ? "input-error" : ""}
          />
          <input 
            type="password" 
            placeholder="Confirm Password" 
            value={confirm} 
            onChange={(e) => setConfirm(e.target.value)} 
            className={errorMsg ? "input-error" : ""}
          />
        </div>
        <div className="modal-actions">
          <button onClick={onClose} className="btn-cancel">Cancel</button>
          <button onClick={handleSubmit} className="btn-submit">Generate PDF</button>
        </div>
      </div>
    </div>
  );
};

// ================= SPARKLINE COMPONENT =================
const Sparkline = ({ history, width = 200, height = 40, isDegraded }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const w = width;
    const h = height;
    
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, w, h);
    
    if (!history || history.length < 2) return;

    const minVal = Math.min(...history);
    const maxVal = Math.max(...history, minVal + 50);
    const range = maxVal - minVal;
    const stepX = w / (history.length - 1);

    const currentVal = history[history.length - 1];
    const isBad = currentVal > 3000 || currentVal === 0 || isDegraded;
    
    const lineColor = isBad ? "#ef4444" : (currentVal > 1000 ? "#f59e0b" : "#00eaff");

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    if (isBad) {
      gradient.addColorStop(0, "rgba(239, 68, 68, 0.5)");
      gradient.addColorStop(1, "rgba(239, 68, 68, 0)");
    } else {
      gradient.addColorStop(0, "rgba(0, 234, 255, 0.4)");
      gradient.addColorStop(1, "rgba(0, 234, 255, 0)");
    }

    ctx.beginPath();
    history.forEach((val, i) => {
      const x = i * stepX;
      const normalizedY = (val - minVal) / (range || 1); 
      const y = h - (normalizedY * h);
      if (i === 0) ctx.moveTo(x, y);
      else {
        const prevX = (i - 1) * stepX;
        const prevVal = history[i - 1];
        const prevNormalizedY = (prevVal - minVal) / (range || 1);
        const prevY = h - (prevNormalizedY * h);
        const cp1x = prevX + (x - prevX) / 2;
        const cp1y = prevY;
        const cp2x = prevX + (x - prevX) / 2;
        const cp2y = y;
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y);
      }
    });

    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.shadowBlur = 10;
    ctx.shadowColor = lineColor;
    ctx.stroke();
    ctx.shadowBlur = 0;

  }, [history, width, height, isDegraded]);

  return (
    <div className="chart-container">
      <canvas 
        ref={canvasRef} 
        width={width} 
        height={height} 
        style={{ width: "100%", height: "100%", display: "block" }} 
      />
    </div>);
};
// ================= ADVANCED PROFESSIONAL ALERT DASHBOARD COMPONENT =================
// ================= ADVANCED PROFESSIONAL ALERT DASHBOARD COMPONENT =================
const AlertDashboardComponent = ({ onBack, token }) => {
    const [view, setView] = useState('rule-config');
    const [loading, setLoading] = useState(true);
    const [historyFilter, setHistoryFilter] = useState('all'); 

    // Data
    const [rules, setRules] = useState([]);
    const [history, setHistory] = useState([]);
    const [domains, setDomains] = useState([]);
    
    // Store the full status object for real-time checks
    const [monitors, setMonitors] = useState({ 
        targets: [], 
        current_statuses: {}, 
        current_latencies: {} 
    }); 
    
    // Form State
    const [formData, setFormData] = useState({
        name: "",
        type: "service",
        target_id: "", 
        condition: "status_down",
        threshold: "",
        severity: "critical",
        channel: "email"
    });

    // State for Clear History Confirmation
    const [showClearConfirm, setShowClearConfirm] = useState(false);

    // State for Delete Rule Confirmation Modal
    const [deleteRuleModal, setDeleteRuleModal] = useState({ isOpen: false, id: null });

    // Ref to store IDs of cleared logs
    const ignoredHistoryIdsRef = useRef(new Set());

    // ================= DEBOUNCE LOGIC =================
    const threatCounterRef = useRef({}); 
    const CONSECUTIVE_FAILURES_THRESHOLD = 2; 

    // ================= LIVE LOGIC: ONLY FOR "ACTIVE THREATS" =================
        // ================= LIVE LOGIC: ONLY FOR "ACTIVE THREATS" =================
    const getLiveViolations = () => {
        const violations = [];
        const targetsToCheck = monitors.targets || [];

        // --- HELPER: Robust Domain Cleaning ---
        const getCleanDomain = (url) => {
            if (!url) return "";
            return url.replace(/.*:\/\//, '').split('/')[0].split('@').pop().trim().toLowerCase();
        };

        // --- HELPER: ROBUST RULE MATCHING ---
        const ruleAppliesToTarget = (rule, target) => {
            const cleanRule = getCleanDomain(rule.target_url);
            const cleanTarget = getCleanDomain(target);
            
            if (!cleanRule || !cleanTarget) return false;

            // 1. Exact Match
            if (cleanRule === cleanTarget) return true;
            
            // 2. Subdomain Match (sub.example.com matches example.com)
            if (cleanTarget.endsWith("." + cleanRule)) return true;
            
            // 3. Reverse Subdomain Match
            if (cleanRule.endsWith("." + cleanTarget)) return true;
            
            // 4. Contains Fallback (Handles "m.testexample.com" matching "testexample.com")
            if (cleanTarget.includes(cleanRule) && cleanRule.length > 3) return true;

            return false;
        };

        // --- EVALUATION LOOP ---
        targetsToCheck.forEach(target => {
            const currentStatus = monitors.current_statuses ? monitors.current_statuses[target] : "Unknown";
            const currentLatency = monitors.current_latencies ? monitors.current_latencies[target] : 0;
            
            let isThreat = false;
            let threatSeverity = 'info';
            let threatMessage = '';
            let matchingRuleId = "SYSTEM";

            // --- 1. CHECK USER DEFINED RULES ---
            const matchedRules = rules.filter(r => 
                r.type === 'service' && r.is_active && ruleAppliesToTarget(r, target)
            );

            if (matchedRules.length > 0) {
                for (const rule of matchedRules) {
                    const condition = rule.condition; 
                    
                    // Check: STATUS DOWN (Expanded Keywords)
                    if (condition === 'status_down' || condition === 'http_error') {
                        // Check for a wider range of "Down" keywords
                        const downKeywords = ["DOWN", "ERROR", "TIMEOUT", "REFUSED", "NOT FOUND", "CRITICAL", "CONNECTION REFUSED"];
                        const isDown = downKeywords.some(kw => currentStatus.toUpperCase().includes(kw));

                        if (isDown) {
                            isThreat = true;
                            threatSeverity = rule.severity || 'critical';
                            threatMessage = `[${threatSeverity.toUpperCase()}] ${target} is unreachable. Status: ${currentStatus}`;
                            matchingRuleId = rule.id;
                            break;
                        }
                    }
                    
                    // Check: RESPONSE TIME HIGH
                    else if (condition === 'response_time_high') {
                        const threshStr = rule.threshold || "> 1000";
                        let limit = 1000;
                        let operator = ">";
                        
                        if (threshStr.includes(">=")) { operator = ">="; limit = parseInt(threshStr.replace(">=", "").replace("ms", "")); }
                        else if (threshStr.includes(">")) { operator = ">"; limit = parseInt(threshStr.replace(">", "").replace("ms", "")); }
                        else if (threshStr.includes("<=")) { operator = "<="; limit = parseInt(threshStr.replace("<=", "").replace("ms", "")); }
                        else if (threshStr.includes("<")) { operator = "<"; limit = parseInt(threshStr.replace("<", "").replace("ms", "")); }

                        if (isNaN(limit)) limit = 1000;

                        let isBreached = false;
                        if (operator === ">=" && currentLatency >= limit) isBreached = true;
                        else if (operator === ">" && currentLatency > limit) isBreached = true;
                        else if (operator === "<=" && currentLatency <= limit) isBreached = true;
                        else if (operator === "<" && currentLatency < limit) isBreached = true;

                        if (isBreached) {
                            isThreat = true;
                            threatSeverity = rule.severity || 'warning';
                            threatMessage = `[${threatSeverity.toUpperCase()}] ${target} latency ${currentLatency.toFixed(0)}ms (Threshold: ${threshStr})`;
                            matchingRuleId = rule.id;
                            break;
                        }
                    }
                }
            } 
            
            // --- 2. FALLBACK: SYSTEM DEFAULT RULES (FIX) ---
            // If no user rules matched, we check for standard critical system states.
            // This ensures "Active Threats" works even without user configuration.
            else {
                const downKeywords = ["DOWN", "ERROR", "TIMEOUT", "REFUSED", "NOT FOUND", "CRITICAL", "CONNECTION REFUSED"];
                const warningKeywords = ["WARNING", "SLOW", "UNSTABLE"];

                const isDown = downKeywords.some(kw => currentStatus.toUpperCase().includes(kw));
                const isWarning = warningKeywords.some(kw => currentStatus.toUpperCase().includes(kw));

                if (isDown) {
                    isThreat = true;
                    threatSeverity = 'critical';
                    threatMessage = `[SYSTEM CRITICAL] ${target} is unreachable. Status: ${currentStatus}`;
                    matchingRuleId = "SYSTEM-AUTO";
                } else if (isWarning) {
                    isThreat = true;
                    threatSeverity = 'warning';
                    threatMessage = `[SYSTEM WARNING] ${target} is experiencing issues. Status: ${currentStatus}`;
                    matchingRuleId = "SYSTEM-AUTO";
                }
            }

            // --- DEBOUNCE LOGIC: Update Counters ---
            if (isThreat) {
                threatCounterRef.current[target] = (threatCounterRef.current[target] || 0) + 1;
            } else {
                threatCounterRef.current[target] = Math.max(0, (threatCounterRef.current[target] || 0) - 1);
            }

            // Only show as Active Threat if failures exceed threshold (2 consecutive checks)
            const count = threatCounterRef.current[target] || 0;
            
            if (count >= 2) {
                if (!violations.find(item => item.id === target)) {
                    violations.push({
                        id: target,
                        time: new Date().toISOString(),
                        rule_id: matchingRuleId,
                        channel: "Real-Time",
                        message: threatMessage,
                        severity: threatSeverity,
                        source: 'live'
                    });
                }
            }
        });

        return violations;
    };

      
            
           

       

    // Fetch Data
    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [token]); 

    const fetchData = async () => {
        try {
            const headers = { 'Authorization': `Bearer ${token}` };
            
            const [rRes, hRes, dRes, sRes] = await Promise.all([
                fetch("http://localhost:8000/alerts/rules", { headers }),
                fetch("http://localhost:8000/alerts/history?limit=1000", {headers }),
                fetch("http://localhost:8000/domain/list", { headers }),
                fetch("http://localhost:8000/status", { headers }) 
            ]);

            if (rRes.ok) setRules(await rRes.json());
            if (hRes.ok) {
                const newHistory = await hRes.json();
                const visibleHistory = newHistory.filter(h => !ignoredHistoryIdsRef.current.has(h.id));
                setHistory(visibleHistory); 
            }
            if (dRes.ok) setDomains(await dRes.json());
            
            if (sRes.ok) {
                const statusData = await sRes.json();
                setMonitors(statusData);
            }
            setLoading(false);
        } catch (e) {
            console.error("Failed to load alert data", e);
            if(window.showToast) window.showToast("Failed to load data", "error");
        }
    };

    // --- Handle Delete Rule ---
    const handleDeleteRule = (ruleId) => {
        setDeleteRuleModal({ isOpen: true, id: ruleId });
    };

    const handleConfirmDeleteRule = async () => {
        const { id } = deleteRuleModal;
        if (!id) return;

        try {
            const res = await fetch(`http://localhost:8000/alerts/rules/${id}`, {
                method: "DELETE",
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.ok) {
                setRules(prev => prev.filter(r => r.id !== id));
                if(window.showToast) window.showToast("Rule Deleted", "success");
            } else {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to delete rule");
            }
        } catch (e) {
            console.error(e);
            if(window.showToast) window.showToast(e.message || "Network error", "error");
        } finally {
            setDeleteRuleModal({ isOpen: false, id: null });
        }
    };

    // --- Clear History Handler ---
    const handleConfirmClear = async () => {
        try {
            const res = await fetch("http://localhost:8000/alerts/history", {
                method: "DELETE",
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to clear history from server.");
            }

            setHistory([]);
            ignoredHistoryIdsRef.current.clear(); 
            setShowClearConfirm(false);

            if(window.showToast) window.showToast("Incident Log Cleared (Database Synced)", "success");

        } catch (e) {
            console.error("Backend Clear Failed:", e);
            alert("Error: Could not clear history from server.\n" + e.message);
        }
    };

    const handleSubmitRule = async (e) => {
        e.preventDefault();
        
        let payload = { ...formData };
        
        if (payload.type === "service") {
            payload.target_url = formData.target_id; 
            payload.target_id = null; 
        } else if (payload.type === "domain") {
            const parsedId = parseInt(payload.target_id, 10);
            payload.target_id = isNaN(parsedId) ? null : parsedId;
        } else {
            payload.target_id = null;
        }

        if (payload.condition === "status_down") {
            payload.threshold = null;
        } else if (!payload.threshold || payload.threshold.trim() === "") {
            payload.threshold = null;
        }

        if (payload.type === "domain") {
            if (payload.condition === "domain_expiring" && !payload.threshold) {
                payload.threshold = "< 30 days";
        } else if (!payload.threshold) {
                payload.threshold = "Any Change"; 
            }
        }

        try {
            const res = await fetch("http://localhost:8000/alerts/rules", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                const newRule = await res.json();
                setRules(prev => [...prev, newRule]);
                if(window.showToast) window.showToast("Alert Rule Deployed", "success");
                setView('rule-config'); 
                resetForm();
            } else {
                const err = await res.json().catch(() => ({ detail: "Unknown error" }));
                if(window.showToast) window.showToast(`Error: ${err.detail}`, "error");
            }
        } catch (e) {
            console.error(e);
            if(window.showToast) window.showToast("Network error while creating rule", "error");
        }
    };

    const resetForm = () => {
        setFormData({
            name: "",
            type: "service",
            target_id: "",
            condition: "status_down",
            threshold: "",
            severity: "critical",
            channel: "email"
        });
    };
    
    const handleOpenCreateRule = (type) => {
        resetForm();
        setFormData(prev => ({
            ...prev,
            type: type,
            condition: type === 'domain' ? 'domain_expiring' : 'status_down',
            threshold: type === 'domain' ? '< 30 days' : '> 1000'
        }));
        setView('create-rule');
    };

    // --- Render Helpers ---
    const getSeverityColor = (sev) => {
        switch(sev) {
            case 'critical': return '#8B0000';
            case 'high': return '#FF0000';
            case 'warning': return '#FFA500'; 
            case 'info': return '#17A2B8';
            default: return 'var(--text-muted)';
        }
    };

    const getSeverityClass = (sev) => {
        switch(sev) {
            case 'critical': return 'sev-critical';
            case 'high': return 'sev-high';
            case 'warning': return 'sev-warning';
            case 'info': return 'sev-info';
            default: return 'sev-info';
        }
    };

    // --- Sidebar ---
    const renderSidebar = () => (
        <aside className="alert-sidebar-pro">
            <div className="alert-sidebar-logo">
                <span className="logo-icon">🛡️</span>
                <div>
                    <h2>SECURITY CENTER</h2>
                    <div className="status-badge pulse">SYSTEM ONLINE</div>
                </div>
            </div>
            <nav className="alert-nav-pro">
                <div className={`alert-nav-item ${view === 'rule-config' ? 'active' : ''}`} onClick={() => { setView('rule-config'); }}>
                    <span className="nav-icon">⚙️</span>
                    <span className="nav-text">Rules</span>
                </div>
                <div className={`alert-nav-item ${view === 'active-alerts' ? 'active' : ''}`} onClick={() => { setView('active-alerts'); }}>
                    <span className="nav-icon">🚨</span>
                    <span className="nav-text">Active Threats</span>
                </div>
                <div className={`alert-nav-item ${view === 'history' ? 'active' : ''}`} onClick={() => { setView('history'); }}>
                    <span className="nav-icon">📜</span>
                    <span className="nav-text">Audit Log</span>
                </div>
            </nav>
            <div className="alert-footer-pro">
                <button onClick={onBack} className="btn-back-alert">← Exit Dashboard</button>
            </div>
        </aside>
    );

    // --- View 1: Configuration ---
    const renderRuleConfigView = () => {
        const getTargetName = (rule) => {
            if (rule.target_url) return rule.target_url;
            if (rule.target_id) {
                const domain = domains.find(d => d.id === rule.target_id);
                return domain ? domain.domain_name : `ID: ${rule.target_id}`;
            }
            return "Unknown Target";
        };

        const formatTriggerDetails = (rule) => {
            if (rule.type === 'service') {
                if (rule.condition === 'status_down') return 'Any Error / Down';
                if (rule.condition === 'response_time_high') {
                    return `Latency ${rule.threshold ? `> ${rule.threshold}ms` : '> Threshold'}`;
                }
            } 
            if (rule.condition === 'smart_anomaly') {
                 return 'ML Pattern Deviation (Z-Score/LSTM)';
        }
            else if (rule.type === 'domain') {
                if (rule.condition === 'domain_expiring') {
                    return `Expires ${rule.threshold ? `< ${rule.threshold}` : 'Soon'}`;
                }
                if (rule.condition === 'dns_changed') return 'DNS Changed';
                if (rule.condition === 'whois_changed') return 'WHOIS Changed';
            }
            return rule.condition;
        };

        return (
            <main className="alert-main-pro">
                <header className="alert-header-pro">
                    <div>
                        <h3>Alert Rules</h3>
                        <p className="subtext">Manage automated response triggers</p>
                    </div>
                </header>

                <div className="alert-config-layout">
                    <div className="config-creation-zone">
                        <h4>Create New Rule</h4>
                        <div className="protocol-cards-grid">
                            <div className="protocol-card-pro" onClick={() => handleOpenCreateRule('service')}>
                                <div className="card-glow blue"></div>
                                <div className="card-content">
                                    <div className="icon-box blue">📡</div>
                                    <h5>Uptime Monitor</h5>
                                    <p>Track latency and heartbeat failures.</p>
                                </div>
                                <div className="action-arrow">→</div>
                            </div>
                            <div className="protocol-card-pro" onClick={() => handleOpenCreateRule('domain')}>
                                <div className="card-glow green"></div>
                                <div className="card-content">
                                    <div className="icon-box green">🌐</div>
                                    <h5>Asset Tracking</h5>
                                    <p>Track expiration and domain risk.</p>
                                </div>
                                <div className="action-arrow">→</div>
                            </div>
                            <div className="protocol-card-pro disabled">
                                <div className="card-glow orange"></div>
                                <div className="card-content">
                                    <div className="icon-box orange">🛡️</div>
                                    <h5>Threat Detection</h5>
                                    <p>WAF & Intrusion Signatures (Locked)</p>
                                </div>
                                <div className="lock-icon">🔒</div>
                            </div>
                        </div>
                    </div>

                    <div className="config-list-zone">
                        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'15px'}}>
                            <h4>Active Rules ({rules.length})</h4>
                        </div>
                        
                        {rules.length === 0 ? (
                            <div className="empty-state-pro">No active Rules found.</div>
                        ) : (
                            <div className="rules-grid-pro">
                                {rules.map(rule => (
                                    <div key={rule.id} className="rule-card-pro">
                                        <div className={`rule-status-bar ${getSeverityClass(rule.severity)}`}></div>
                                        <div className="rule-header-row">
                                            <h5>{rule.name}</h5>
                                            <span className={`rule-tag ${getSeverityClass(rule.severity)}`}>
                                                {rule.severity}
                                            </span>
                                        </div>
                                        <div className="rule-info-grid">
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">TYPE</span>
                                                <span className="rule-info-value">
                                                    <span>{rule.type === 'service' ? '📡' : '🌐'}</span>
                                                    {rule.type}
                                                </span>
                                            </div>
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">TARGET</span>
                                                <div className="rule-info-value">
                                                    <span className="rule-target-value" title={getTargetName(rule)}>
                                                        {getTargetName(rule)}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">TRIGGER</span>
                                                <span className="rule-info-value val-condition">
                                                    {formatTriggerDetails(rule)}
                                                </span>
                                            </div>
                                        </div>
                                        <div className="rule-footer">
                                            <span style={{fontSize:'0.7rem', color:'var(--text-muted)', fontFamily: 'monospace'}}>
                                                ID: #{rule.id}
                                            </span>
                                            <button 
                                                onClick={() => handleDeleteRule(rule.id)}
                                                className="btn-rule-delete"
                                            >
                                                Delete
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </main>
        );
    };

    const renderCreateRuleView = () => {
        const isService = formData.type === 'service';
        return (
        <main className="alert-main-pro">
            <header className="alert-header-pro" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <h3>{isService ? "New Uptime Protocol" : "New Asset Protocol"}</h3>
                </div>
                <button onClick={() => setView('rule-config')} className="btn-secondary-alert">Cancel</button>
            </header>
            
            <div className="creation-form-wrapper">
                <form onSubmit={handleSubmitRule}>
                    <div className="form-group">
                        <label>Rule Name</label>
                        <input 
                            required 
                            className="input-pro" 
                            placeholder="e.g. API Gateway Latency" 
                            value={formData.name} 
                            onChange={e => setFormData({...formData, name: e.target.value})} 
                        />
                    </div>

                    <div className="form-group">
                        <label>{isService ? 'TARGET URL' : 'DOMAIN ASSET'}</label>
                        {isService ? (
                            <input 
                                required 
                                className="input-pro" 
                                placeholder="https://api.sentinel.ai" 
                                value={formData.target_id} 
                                onChange={e => setFormData({...formData, target_id: e.target.value})} 
                            />
                        ) : (
                            <select 
                                required
                                className="input-pro" 
                                value={formData.target_id} 
                                onChange={(e) => setFormData({...formData, target_id: e.target.value})}
                            >
                                <option value="">-- Select Domain --</option>
                                {domains.map(d => (
                                    <option key={d.id} value={d.id}>{d.domain_name}</option>
                                ))}
                            </select>
                        )}
                    </div>

                    <div className="form-group">
                        <label>CONDITION</label>
                        <select 
                            required
                            className="input-pro" 
                            value={formData.condition} 
                            onChange={(e) => setFormData({...formData, condition: e.target.value, threshold: ''})} 
                        >
                            {isService ? (
                                <>
                                    <option value="status_down">Service Down (Any Error)</option>
                                    <option value="response_time_high">High Response Time</option>
                                    <option value="smart_anomaly">Smart Anomaly Detected (AI/ML)</option>
                                </>
                            ) : (
                                <>
                                    <option value="domain_expiring">Domain Expiring Soon</option>
                                    <option value="dns_changed">DNS Records Changed</option>
                                    <option value="whois_changed">WHOIS Data Changed</option>
                                </>
                            )}
                        </select>
                    </div>

                    {isService && formData.condition === "response_time_high" && (
                        <div className="form-group">
                            <label>THRESHOLD (MS)</label>
                            <input 
                                type="number"
                                required
                                className="input-pro" 
                                placeholder="e.g. 500"
                                value={formData.threshold}
                                onChange={e => setFormData({...formData, threshold: e.target.value})}
                            />
                        </div>
                    )}

                    {!isService && formData.condition === "domain_expiring" && (
                        <div className="form-group">
                            <label>EXPIRATION WINDOW (DAYS)</label>
                            <input 
                                type="number"
                                className="input-pro" 
                                placeholder="e.g. 30" 
                                value={formData.threshold}
                                onChange={e => setFormData({...formData, threshold: e.target.value})}
                            />
                        </div>
                    )}

                    <div className="form-group">
                        <label>SEVERITY</label>
                        <div className="severity-selector">
                            {['critical', 'high', 'warning', 'info'].map(lvl => (
                                <div 
                                    key={lvl} 
                                    className={`severity-opt ${formData.severity === lvl ? 'active' : ''}`} 
                                    onClick={() => setFormData({...formData, severity: lvl})}
                                    style={{borderColor: formData.severity === lvl ? getSeverityColor(lvl) : 'transparent'}}
                                >
                                    {lvl}
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="form-actions">
                        <button 
                            type="button" 
                            onClick={() => setView('rule-config')} 
                            className="btn-cancel-alert-red"
                            style={{ flex: 30, height: '48px' }} 
                        >
                            Discard
                        </button>
                        <button 
                            type="submit" 
                            className="btn-deploy-alert" 
                            style={{ flex: 30, height: '48px' }}
                        >
                            Deploy Rule
                        </button>
                    </div>
                </form>
            </div>
        </main>
        );
    };

        // --- View 3: Active Threats (Live Only) ---
    const renderActiveAlertsView = () => {
        // Get violations from Live Monitoring (For explicitly tracked targets)
        // This logic checks the CURRENT status against CURRENT rules.
        const activeItems = getLiveViolations();
        
        // STRICTLY LIVE LIST
        // We DO NOT merge with database history ('recentAlerts') here.
        // The "Audit Log" tab handles history.
        // This tab is strictly for threats that are happening RIGHT NOW.
        // If a site is UP, it will not appear here, even if it was down 5 minutes ago.
        const allActiveThreats = activeItems;
        
        // Sort by time (Newest first)
        allActiveThreats.sort((a, b) => new Date(b.time) - new Date(a.time));

        return (
            <main className="alert-main-pro">
                <header className="alert-header-pro">
                    <div>
                        <h3>Active Threats</h3>
                        <p className="subtext">Real-time status of currently failing services.</p>
                    </div>
                </header>

                {allActiveThreats.length === 0 ? (
                    <div className="empty-state-pro secure">
                        <div className="secure-icon">🛡️</div>
                        <h4>SYSTEM SECURE</h4>
                        <p>No active violations detected across all monitored targets.</p>
                    </div>
                ) : (
                    <div className="threat-feed">
                        {allActiveThreats.map(h => (
                            <div key={h.id || h.source + h.message} className="threat-card">
                                <div className={`threat-indicator ${getSeverityClass(h.severity)}`}></div>
                                <div className="threat-content">
                                    <div className="threat-meta">
                                        <span className="time-stamp">{new Date(h.time).toLocaleString()}</span>
                                        <span className={`threat-sev ${getSeverityClass(h.severity)}`}>
                                            {h.severity.toUpperCase()}
                                        </span>
                                    </div>
                                    <div className="threat-message">{h.message}</div>
                                    <div className="threat-details">
                                        <span>Rule ID: #{h.rule_id}</span>
                                        <span>Source: Live Monitor</span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </main>
        );
    };



    // --- View 4: History (Strictly Database) ---
    const renderHistoryView = () => {
        // 1. Filter the Database History based on the UI filter
        const filteredHistory = history.filter(h => {
            if (historyFilter === 'all') return true;
            return h.severity === historyFilter;
        });

        // 2. Sort by time (Newest first)
        const displayList = [...filteredHistory].sort((a, b) => new Date(b.time) - new Date(a.time));

        // 3. Calculate stats based on the filtered list
        const cardData = [
            { id: 'all', label: 'All Events', count: displayList.length, color: 'var(--text-muted)' },
            { id: 'critical', label: 'Critical', count: displayList.filter(h => h.severity === 'critical').length, color:'#8B0000' },
            { id: 'high', label: 'High', count: displayList.filter(h => h.severity === 'high').length, color:'#FF0000' },
            { id: 'warning', label: 'Warning', count: displayList.filter(h => h.severity === 'warning').length, color:'#FFA500' },
            { id: 'info', label: 'Info', count: displayList.filter(h => h.severity === 'info').length, color: '#17A2B8' },
        ];

        return (
            <main className="alert-main-pro">
                <header className="alert-header-pro">
                    <div>
                        <h3>Incident Log</h3>
                        <p className="subtext">Permanent database records</p>
                    </div>
                    {history.length > 0 && (
                        <button onClick={() => setShowClearConfirm(true)} className="btn-clear-alert">
                            Clear Log
                        </button>
                    )}
                </header>

                <div className="history-stats-grid">
                    {cardData.map(card => (
                        <div 
                            key={card.id}
                            className={`h-stat-card-pro ${historyFilter === card.id ? 'active' : ''}`}
                            onClick={() => setHistoryFilter(card.id)}
                            style={{ borderColor: historyFilter === card.id ? card.color : 'rgba(255,255,255,0.05)' }}
                        >
                            <div className="h-stat-count" style={{ color: card.color }}>{card.count}</div>
                            <div className="h-stat-label">{card.label}</div>
                        </div>
                    ))}
                </div>

                <div className="audit-list-pro">
                    {displayList.length === 0 ? (
                        <div className="empty-state-pro">
                            <div className="empty-icon">📭</div>
                            <p>No records found in database history.</p>
                        </div>
                    ) : (
                        displayList.map(h => (
                            <div key={h.id} className="audit-row-pro">
                                <div className="audit-time-pro">
                                    <div className="date-text">{new Date(h.time).toLocaleDateString()}</div>
                                    <div className="time-text">{new Date(h.time).toLocaleTimeString()}</div>
                                </div>
                                <div className="audit-body-pro">
                                    <div className="audit-header-pro">
                                        <span className={`audit-sev-tag ${getSeverityClass(h.severity)}`}>{h.severity}</span>
                                        <span className="audit-id">#{h.rule_id}</span>
                                    </div>
                                    <div className="audit-msg-pro">{h.message || "Standard System Check"}</div>
                                </div>
                                <div className="audit-channel-pro">
                                    {h.channel}
                                </div>
                            </div>
                        ))
                    )}
                </div>

                <ConfirmModal
                    isOpen={showClearConfirm}
                    onClose={() => setShowClearConfirm(false)}
                    onConfirm={handleConfirmClear}
                    title="Clear Incident Log"
                    message="Are you sure you want to permanently clear the incident log history? This action will delete records from the database."
                />
            </main>
        );
    };
    
    if (loading) return <div className="loading-overlay">INITIALIZING SECURITY RULES...</div>;

    return (
        <div className="alert-dashboard-pro-layout">
            {renderSidebar()}
            {view === 'rule-config' && renderRuleConfigView()}
            {view === 'create-rule' && renderCreateRuleView()}
            {view === 'active-alerts' && renderActiveAlertsView()}
            {view === 'history' && renderHistoryView()}
            
            <ConfirmModal
                isOpen={deleteRuleModal.isOpen}
                onClose={() => setDeleteRuleModal({ isOpen: false, id: null })}
                onConfirm={handleConfirmDeleteRule}
                title="Delete Alert Rule"
                message="Are you sure you want to permanently remove this Alert Rule ? This action cannot be undone."
            />
        </div>
    );
};
    

// ================= UPGRADED DOMAIN TRACKING COMPONENT =================

const ExpiryCountdown = ({ label, dateStr }) => {
  if (!dateStr) return <div className="expiry-badge">N/A</div>;

  const targetDate = new Date(dateStr);
  const now = new Date();
  const diffTime = targetDate - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  let statusClass = "status-green"; 
  if (diffDays <= 7) statusClass = "status-red";
  else if (diffDays <= 30) statusClass = "status-yellow";

  return (
    <div className={`expiry-info ${statusClass}`}>
      <span className="expiry-label">{label}</span>
      <span className="expiry-days">
        {diffDays < 0 ? "Expired" : `${diffDays} Days`}
      </span>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
        ({formatDate(dateStr)})
      </span>
    </div>
  );
};

// ... existing code ...

const DEFAULT_MANUAL_DATA = {
  registrar: "",
  regDate: "",
  expirationDate: "",
  autoRenew: false,
  dnsProvider: "",
  hostingProvider: "",
  sslProvider: "",
  purpose: "production",
  riskLevel: "Medium",
  primaryOwner: "",
  backupOwner: "",
  team: "",
  department: "",
  security: {
    // --- Existing ---
    mfa: false,
    lock: false,
    dnssec: false,
    backupContact: false,
    
    // --- NEW: Registrar Security ---
    registrarLock: false,
    registryLock: false,
    
    // --- NEW: DNS Security ---
    secureNameservers: false,
    noDanglingRecords: false,
    
    // --- NEW: Web Security ---
    tlsVersion: false,
    sslExpiry: false,
    hsts: false,
    
    // --- NEW: Email Security ---
    spf: false,
    dkim: false,
    dmarc: false,
    
    // --- NEW: Threat Monitoring ---
    blacklistCheck: false,
    phishingDetection: false,
    typosquatting: false
  },
  notes: []
};

// ... existing code ...

const DomainTrackingComponent = ({ onBack, token, username }) => {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [detailData, setDetailData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAdding, setIsAdding] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  
  // UI States
  const [activeDetailTab, setActiveDetailTab] = useState("overview"); 
  const [isEditMode, setIsEditMode] = useState(false);
  const [expandedDns, setExpandedDns] = useState({});
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);
  
  // NEW: State for Domain Add Modal
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  // NEW: State for Delete Confirmation Modal
  const [deleteModal, setDeleteModal] = useState({ isOpen: false, id: null });

  const [domainManualDataMap, setDomainManualDataMap] = useState({});

  const currentManualData = useMemo(() => {
    if (!selectedDomain) return DEFAULT_MANUAL_DATA;
    return domainManualDataMap[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA;
  }, [selectedDomain, domainManualDataMap]);

  const fetchDomains = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8000/domain/list", {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) {
        if (res.status === 401) {
            alert("Session expired. Please login again.");
            window.location.reload();
        }
        setDomains([]);
        setLoading(false);
        return;
      }
      const data = await res.json();
      setDomains(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch domains", err);
      setDomains([]);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchDomains();
    const interval = setInterval(fetchDomains, 60000);
    return () => clearInterval(interval);
  }, [token, fetchDomains]);

  const handleGlobalDomainReport = () => {
    if (!selectedDomain) {
      alert("Please select a domain from the sidebar first to generate a report.");
      return;
    }
    setIsPwdModalOpen(true);
  };

  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch(`http://localhost:8000/domain/report/${selectedDomain.id}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password })
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.detail || "Failed to generate report");
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${selectedDomain.domain_name}_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report: " + err.message);
    }
  };

  // UPDATED: handleAdd now accepts domain from modal
  const handleAdd = async (domainName) => {
    if (!domainName) return;
    setIsAdding(true);
    try {
      const res = await fetch("http://localhost:8000/domain/add", {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(domainName),
      });
      if (res.ok) {
        const data = await res.json();
        setIsAddModalOpen(false); // Close modal on success
        if(window.showToast) window.showToast(`${data.message}`, "success");
        await fetchDomains();
      } else {
        const errorData = await res.json().catch(() => ({}));
        setIsAddModalOpen(false);
        if(window.showToast) window.showToast(`Failed to add domain: ${errorData.detail || "Unknown error"}`, "error");
      }
    } catch (err) {
      setIsAdding(false);
      setIsAddModalOpen(false);
      if(window.showToast) window.showToast("Network error adding domain", "error");
    } finally {
      setIsAdding(false);
    }
  };

  // UPDATED: Opens the professional modal instead of window.confirm
  const handleDelete = (e, id) => {
    e.stopPropagation();
    // Set the state to open the modal with the specific ID
    setDeleteModal({ isOpen: true, id: id });
  };

  // NEW: Handles the actual deletion after confirmation
  const handleConfirmDelete = async () => {
    const { id } = deleteModal;
    if (!id) return;

    try {
      const res = await fetch(`http://localhost:8000/domain/${id}`, {
        method: "DELETE",
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok || res.status === 204) {
        // If the deleted domain was currently selected, clear selection
        if (selectedDomain?.id === id) {
          setSelectedDomain(null);
          setDetailData(null);
        }
        if(window.showToast) window.showToast("Domain deleted successfully", "success");
        await fetchDomains();
      } else {
        let errorText = "Failed to delete domain.";
        try {
            const errData = await res.json();
            if (errData.detail) errorText += ` Server says: ${errData.detail}`;
        } catch (e) {
            errorText += ` Server status: ${res.status} ${res.statusText}`;
        }
        if(window.showToast) window.showToast(errorText, "error");
      }
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("Network error while deleting. Please check console.", "error");
    } finally {
      // Always close the modal and clear the ID
      setDeleteModal({ isOpen: false, id: null });
    }
  };

  const handleSelect = async (domainId) => {
    const domain = domains.find((d) => d.id === domainId);
    setSelectedDomain(domain);
    setExpandedDns({});
    setDetailData(null); 

    try {
      const res = await fetch(`http://localhost:8000/domain/detail/${domainId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Failed to fetch details");
      const data = await res.json();
      
      if (data.manual_data && Object.keys(data.manual_data).length > 0) {
          setDomainManualDataMap(prev => ({
              ...prev,
              [domain.domain_name]: {
                  ...DEFAULT_MANUAL_DATA, 
                  ...data.manual_data     
              }
          }));
      } else {
          setDomainManualDataMap(prev => ({
              ...prev,
              [domain.domain_name]: {
                  ...DEFAULT_MANUAL_DATA,
                  registrar: data.registrar || "",
                  regDate: data.creation_date || "",
                  expirationDate: "", 
                  apiExpiration: data.expiration_date 
              }
          }));
      }

      setTimeout(() => setDetailData(data), 100);
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("Could not load details.", "error");
      setDetailData(null);
    }
  };

  const handleRescan = async () => {
    if (!selectedDomain) return;
    setIsScanning(true);
    try {
      const res = await fetch(`http://localhost:8000/domain/scan/${selectedDomain.id}`, {
        method: "POST",
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        await handleSelect(selectedDomain.id);
        await fetchDomains();
      } else {
        throw new Error("Scan failed");
      }
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("❌ Scan failed.", "error");
    } finally {
      setTimeout(() => setIsScanning(false), 1500);
    }
  };

  const toggleDns = (type) => {
    setExpandedDns(prev => ({ ...prev, [type]: !prev[type] }));
  };

  const updateManualField = (key, value) => {
    if (!selectedDomain) return;
    setDomainManualDataMap(prev => ({
      ...prev,
      [selectedDomain.domain_name]: {
        ...(prev[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA),
        [key]: value
      }
    }));
  };

  const updateSecurityField = (key, value) => {
    if (!selectedDomain) return;
    const domainName = selectedDomain.domain_name;
    const prevData = domainManualDataMap[domainName] || DEFAULT_MANUAL_DATA;
    
    const newSecurity = {
        ...(prevData.security || DEFAULT_MANUAL_DATA.security),
        [key]: value
    };

    const newManualData = {
        ...prevData,
        security: newSecurity
    };

    setDomainManualDataMap(prev => ({
      ...prev,
      [domainName]: newManualData
    }));

    saveManualData(true, newManualData);
  };

    const saveManualData = async (isSilent = false, manualPayload = null) => {
    if (!selectedDomain) return;

    // Get the data we intend to save
    let payload = manualPayload || domainManualDataMap[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA;
    
    // --- NEW: Automatic Audit Logging for Asset Tab Saves ---
    // If the user clicked "Save Changes" (Not silent like a checkbox toggle), we add a log entry.
    if (!isSilent) {
        const newNote = {
            date: new Date().toISOString(),
            text: "Asset Profile Updated: Ownership, Infrastructure, or Lifecycle changes saved."
        };

        // Ensure notes array exists and prepend the new note
        const currentNotes = payload.notes || [];
        payload = {
            ...payload,
            notes: [newNote, ...currentNotes] 
        };
    }

    try {
        const res = await fetch(`http://localhost:8000/domain/update-manual/${selectedDomain.id}`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json", 
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Failed to save");
        }
        
        // NEW: Update Local State immediately with the new note
        // This ensures the Security tab refreshes instantly with the new audit entry
        setDomainManualDataMap(prev => ({
            ...prev,
            [selectedDomain.domain_name]: payload
        }));
        
        if (!isSilent) {
            setIsEditMode(false);
            if(window.showToast) window.showToast("Asset Profile Updated & Saved", "success");
        }
    } catch (err) {
        console.error(err);
        if (!isSilent) {
            alert("Error saving data: " + err.message);
        } else {
            console.warn("Silent auto-save failed:", err.message);
        }
    }
  };

  const addNote = () => {
    const text = prompt("Enter note or audit log entry:");
    if (text) {
        const domainName = selectedDomain.domain_name;
        const prevData = domainManualDataMap[domainName] || DEFAULT_MANUAL_DATA;
        const newNotes = [
            ...(prevData.notes || []),
            { date: new Date().toISOString(), text }
        ];
        
        const newManualData = {
            ...prevData,
            notes: newNotes
        };

        setDomainManualDataMap(prev => ({
            ...prev,
            [domainName]: newManualData
        }));

        saveManualData(true, newManualData);
    }
  };

  const riskScoreObj = detailData ? calculateRisk(currentManualData) : { score: 0, riskLevel: "Unknown", color: "gray" };
  
  // Helper: Calculate Domain Age
  const getDomainAge = (dateStr) => {
      if (!dateStr) return "Unknown";
      try {
          const created = new Date(dateStr);
          const now = new Date();
          const diff = now - created;
          const days = Math.floor(diff / (1000 * 60 * 60 * 24));
          const years = Math.floor(days / 365);
          const remainingDays = days % 365;
          if (years > 0) return `${years}y ${remainingDays}d`;
          return `${days}d`;
      } catch(e) { return "Invalid"; }
  };

  // Helper: Extract TLD
  const getTLD = (domain) => {
      if (!domain) return "??";
      const parts = domain.split('.');
      return parts.length > 1 ? parts[parts.length - 1].toUpperCase() : "??";
  };

  return (
    <div className="up-dashboard dashboard-atmosphere" style={{ gridTemplateColumns: "350px 1fr" }}>
      <div className="glow-orb orb-dashboard-1"></div>
      <div className="glow-orb orb-dashboard-2"></div>

      <aside className="up-sidebar">
        <div className="up-sidebar-header" style={{ flexDirection: "column", alignItems: "flex-start", gap: "10px" }}>
            <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "center" }}>
                <h2 style={{margin: 0}}>Domain Assets</h2>
                <div className="up-status-badge live">Live Tracking</div>
            </div>
        </div>

        <div style={{ marginTop: "20px" }}>
          <button 
            onClick={() => setIsAddModalOpen(true)}
            className="up-btn-blue"
            style={{ width: "100%", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "10px" }}
          >
            <span>+</span> Add New Domain
          </button>
        </div>

        <div className="up-nav" style={{ marginTop: "20px", padding: 0 }}>
          {domains.map((d) => (
            <div
              key={d.id}
              className={`nav-item domain-card-item interactive-card ${
                selectedDomain?.id === d.id ? "active-glow" : ""
              }`}
              onClick={() => handleSelect(d.id)}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px", width: "100%" }}>
                
                <div className="health-ring-container" title={`Score: ${d.security_score}`}>
                  <div 
                    className="health-ring"
                    style={{
                      background: `conic-gradient(var(--status-blue) ${d.security_score}%, rgba(255,255,255,0.1) 0)`,
                      borderColor: d.security_score > 50 ? "rgba(255,255,255,0.1)" : "var(--status-red)"
                    }}
                  ></div>
                  <div className="health-dot"></div>
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: "bold", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {d.domain_name}
                  </div>
                </div>

                <button
                  onClick={(e) => handleDelete(e, d.id)}
                  className="icon-btn-delete"
                  title="Delete"
                >
                  ✕
                </button>
              </div>
            </div>
          ))}
          {domains.length === 0 && !loading && (
            <div className="up-empty-state" style={{border: "none", background: "transparent"}}>
              <p>No domains tracked yet.</p>
            </div>
          )}
        </div>

        <div className="up-footer-nav">
          <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
        </div>
      </aside>

      <main className="up-main">
        {detailData ? (
          <div className="fade-in-content">
            <header className="up-header">
              <div>
                  <div style={{display: "flex", alignItems: "center", gap: "15px"}}>
                    <h3 style={{ margin: 0 }}>{detailData.domain_name}</h3>
                    <div style={{
                        padding: "4px 8px", 
                        background: "rgba(0,0,0,0.3)", 
                        border: "1px solid", 
                        borderColor: riskScoreObj.color,
                        borderRadius: "4px",
                        color: riskScoreObj.color,
                        fontSize: "0.7rem",
                        fontWeight: "bold",
                        textTransform: "uppercase"
                    }}>
                        Risk: {riskScoreObj.riskLevel}
                    </div>
                  </div>
                <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                  Last Scanned: {new Date(detailData.last_scanned).toLocaleString()}
                </span>
              </div>
              
              <div style={{ display: "flex", gap: "10px" }}>
                <button 
                    onClick={handleGlobalDomainReport} 
                    className="up-btn-gray" 
                    style={{ fontSize: "0.8rem" }}
                    title="Generate PDF for this domain only"
                >
                    📄 Domain Report
                </button>
                <button 
                    onClick={handleRescan} 
                    className={`up-btn-blue ${isScanning ? 'scanning-btn' : ''}`} 
                    disabled={isScanning}
                >
                    {isScanning ? "Scanning..." : "🔄 Re-Scan Auto"}
                </button>
              </div>
            </header>

            {isScanning && <div className="scan-overlay"><div className="scan-line"></div></div>}

            {/* TABS */}
            <div style={{ display: "flex", gap: "20px", marginBottom: "20px", borderBottom: "1px solid var(--border-color)" }}>
                {['overview', 'asset', 'security'].map(tab => (
                    <div 
                        key={tab}
                        onClick={() => setActiveDetailTab(tab)}
                        style={{
                            padding: "10px 20px",
                            cursor: "pointer",
                            textTransform: "uppercase",
                            fontSize: "0.8rem",
                            fontWeight: "bold",
                            color: activeDetailTab === tab ? "var(--status-blue)" : "var(--text-muted)",
                            borderBottom: activeDetailTab === tab ? "2px solid var(--status-blue)" : "2px solid transparent",
                            transition: "0.3s"
                        }}
                    >
                        {tab}
                    </div>
                ))}
            </div>

            {/* TAB CONTENT */}
            {activeDetailTab === "overview" && (
                <div className="fade-in-content">
                    <div className="analytics-grid">
                        
                        {/* 1. Ownership Card (Manual) */}
                        {(currentManualData.primaryOwner || currentManualData.department) && (
                            <div className="analytics-card glass-card-hover" style={{borderTop: "3px solid var(--status-blue)"}}>
                                <div className="card-header">
                                    <span className="card-icon">👥</span>
                                    <h4>Ownership (Manual)</h4>
                                </div>
                                <div className="card-body">
                                    <div className="status-row">
                                        <span>Primary Owner:</span>
                                        <span style={{fontWeight:"bold", color:"white"}}>{currentManualData.primaryOwner || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Backup Owner:</span>
                                        <span>{currentManualData.backupOwner || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Department:</span>
                                        <span className="text-glow">{currentManualData.department || "---"}</span>
                                    </div>
                                    <div style={{marginTop: "10px", fontSize: "0.7rem", color: "var(--text-muted)"}}>
                                        * Edit in Asset Profile tab
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* 2. NEW: Domain Vitality Card (Replaces SSL) */}
                        <div className="analytics-card glass-card-hover">
                            <div className="card-header">
                                <span className="card-icon">📅</span>
                                <h4>Domain Vitality</h4>
                            </div>
                            <div className="card-body">
                                <div className="status-row">
                                    <span>Age:</span>
                                    <span style={{fontWeight:"bold", color:"var(--status-blue)"}}>{getDomainAge(currentManualData.regDate || detailData.creation_date)}</span>
                                </div>
                                <div className="status-row">
                                    <span>TLD:</span>
                                    <span style={{fontWeight:"bold", color:"var(--status-green)"}}>{getTLD(detailData.domain_name)}</span>
                                </div>
                                <div className="status-row">
                                    <span>Registrar:</span>
                                    <span className="text-glow">
                                        {currentManualData.registrar || detailData.registrar || "Unknown"}
                                    </span>
                                </div>
                                <div style={{marginTop: "15px"}}>
                                    <ExpiryCountdown label="Renewal In" dateStr={currentManualData.expirationDate || detailData.expiration_date} />
                                </div>
                            </div>
                        </div>

                         {/* 3. Infrastructure Providers (Manual) */}
                         {(currentManualData.hostingProvider || currentManualData.dnsProvider) && (
                            <div className="analytics-card glass-card-hover" style={{borderTop: "3px solid var(--status-blue)"}}>
                                <div className="card-header">
                                    <span className="card-icon">🏢</span>
                                    <h4>Providers (Manual)</h4>
                                </div>
                                <div className="card-body">
                                    <div className="status-row">
                                        <span>DNS:</span>
                                        <span style={{fontWeight:"bold"}}>{currentManualData.dnsProvider || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Hosting:</span>
                                        <span style={{fontWeight:"bold"}}>{currentManualData.hostingProvider || "---"}</span>
                                    </div>
                                    <div style={{marginTop: "10px", fontSize: "0.7rem", color: "var(--text-muted)"}}>
                                        * Edit in Asset Profile tab
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* 4. Lifecycle & Purpose (Manual) */}
                        <div className="analytics-card glass-card-hover">
                            <div className="card-header">
                                <span className="card-icon">⚙️</span>
                                <h4>Purpose & Lifecycle</h4>
                            </div>
                            <div className="card-body">
                                <div className="status-row">
                                    <span>Purpose:</span>
                                    <span style={{
                                        background: "rgba(6, 182, 212, 0.1)", 
                                        padding: "2px 8px", 
                                        borderRadius: "4px",
                                        textTransform: "uppercase",
                                        fontSize: "0.75rem",
                                        fontWeight: "bold"
                                    }}>
                                        {currentManualData.purpose}
                                    </span>
                                </div>
                                <div className="status-row">
                                    <span>Auto-Renew:</span>
                                    <span style={{color: currentManualData.autoRenew ? "var(--status-green)" : "var(--status-red)"}}>
                                        {currentManualData.autoRenew ? "Enabled" : "Disabled"}
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* 5. Quick Health (DNS Only) */}
                        <div className="analytics-card glass-card-hover">
                             <div className="card-header">
                                <span className="card-icon">🩺</span>
                                <h4>Quick Health</h4>
                            </div>
                            <div className="card-body" style={{flexDirection: "column", gap: "12px"}}>
                                <div className="health-item interactive-item">
                                    <span className="health-icon">{detailData.dns_records?.A?.length ? '✅' : '⚠️'}</span>
                                    <div className="health-text"><strong>DNS Resolution</strong></div>
                                </div>
                                <div className="health-item interactive-item">
                                    <span className="health-icon">{detailData.registrar ? '✅' : '⚠️'}</span>
                                    <div className="health-text"><strong>WHOIS Data</strong></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                      <h4>DNS Infrastructure (Auto)</h4>
                      {detailData.dns_records && Object.keys(detailData.dns_records).length > 0 ? (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "15px" }}>
                          {Object.entries(detailData.dns_records).map(([type, records]) => (
                            records.length > 0 && (
                              <div key={type} className="dns-box interactive-dns-box">
                                <div className="dns-type">{type} Records ({records.length})</div>
                                <div className="dns-list">
                                    {records.slice(0, expandedDns[type] ? records.length : 3).map((rec, i) => (
                                        <div key={i} className="dns-item interactive-dns-item">{rec}</div>
                                    ))}
                                    {records.length > 3 && (
                                        <div className="dns-more-btn" onClick={() => toggleDns(type)}>
                                            {expandedDns[type] ? `Show less` : `+ ${records.length - 3} more`}
                                        </div>
                                    )}
                                </div>
                              </div>
                            )
                          ))}
                        </div>
                      ) : (
                        <div className="up-empty-state">No DNS records detected.</div>
                      )}
                    </div>
                </div>
            )}

                       {activeDetailTab === "asset" && (
                <div className="fade-in-content">
                    <div className="asset-tab-container">
                        <div className="up-widget glass-widget">
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", borderBottom: "1px solid var(--border-color)", paddingBottom: "15px" }}>
                                <div>
                                    <h3 style={{ margin: 0, color: "white", fontSize: "1.5rem", textTransform: "uppercase" }}>Manual Asset Profile</h3>
                                    <p style={{ margin: "5px 0 0", color: "var(--text-muted)", fontSize: "0.85rem" }}>Manage ownership, infrastructure, and lifecycle metadata.</p>
                                </div>
                                <button 
                                    onClick={() => setIsEditMode(!isEditMode)} 
                                    className={`up-btn-blue ${isEditMode ? 'btn-active-edit' : ''}`} 
                                    style={{ fontSize: "0.8rem", padding: "10px 25px", textTransform: "uppercase", letterSpacing: "1px" }}
                                >
                                    {isEditMode ? "Cancel Edit" : "✎ Edit Profile"}
                                </button>
                            </div>

                            <div className="asset-modules-grid">
                                
                                {/* MODULE 1: IDENTITY & OWNERSHIP */}
                                <div className="asset-module">
                                    <div className="module-header">
                                        <span className="module-icon">👤</span>
                                        <h4>Identity & Ownership</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Primary Owner</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.primaryOwner} 
                                                onChange={(e) => updateManualField('primaryOwner', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Backup Owner</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.backupOwner} 
                                                onChange={(e) => updateManualField('backupOwner', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Department</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.department} 
                                                onChange={(e) => updateManualField('department', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* MODULE 2: INFRASTRUCTURE STACK */}
                                <div className="asset-module">
                                    <div className="module-header">
                                        <span className="module-icon">🏢</span>
                                        <h4>Infrastructure Stack</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Registrar</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.registrar} 
                                                onChange={(e) => updateManualField('registrar', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>DNS Provider</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.dnsProvider} 
                                                onChange={(e) => updateManualField('dnsProvider', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Hosting Provider</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.hostingProvider} 
                                                onChange={(e) => updateManualField('hostingProvider', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* MODULE 3: LIFECYCLE & PURPOSE */}
                                <div className="asset-module full-width">
                                    <div className="module-header">
                                        <span className="module-icon">⚙️</span>
                                        <h4>Lifecycle & Operations</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Purpose</label>
                                            <select 
                                                value={currentManualData.purpose} 
                                                onChange={(e) => updateManualField('purpose', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-select-field" : "cyber-input-readonly"}
                                                style={isEditMode ? {} : {textAlign: 'right', cursor: 'default'}}
                                            >
                                                <option value="production">Production</option>
                                                <option value="staging">Staging</option>
                                                <option value="test">Test</option>
                                                <option value="internal">Internal</option>
                                            </select>
                                        </div>
                                        <div className="data-field-row">
                                            <label>Manual Expiration</label>
                                            <input 
                                                type="date" 
                                                value={currentManualData.expirationDate} 
                                                onChange={(e) => updateManualField('expirationDate', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                            />
                                        </div>
                                        <div className="data-field-row" style={{ alignItems: 'center' }}>
                                            <label style={{ marginBottom: 0 }}>Auto-Renew Status</label>
                                            <label className={`toggle-switch ${currentManualData.autoRenew ? 'active' : ''}`} onClick={() => isEditMode && updateManualField('autoRenew', !currentManualData.autoRenew)}>
                                                <div className="toggle-slider"></div>
                                                <span className="toggle-text">{currentManualData.autoRenew ? "ENABLED" : "DISABLED"}</span>
                                            </label>
                                        </div>
                                    </div>
                                </div>

                            </div>
                            
                            {/* SAVE BUTTON AREA */}
                            {isEditMode && (
                                <div style={{ marginTop: "30px", textAlign: "right", borderTop: "1px dashed var(--border-color)", paddingTop: "20px" }}>
                                    <button onClick={() => saveManualData(false)} className="up-btn-green" style={{fontSize: "0.9rem", padding: "12px 35px"}}>
                                        💾 Save Changes
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

                        {activeDetailTab === "security" && (
                <div className="fade-in-content">
                    <div className="analytics-grid" style={{gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))'}}>
                        
                        {/* 1. RISK SCORE CARD */}
                        <div className="analytics-card glass-card-hover" style={{ gridRow: "span 1" }}>
                             <div className="card-header">
                                <span className="card-icon">📊</span>
                                <h4>Calculated Risk Score</h4>
                            </div>
                            <div style={{ textAlign: "center", padding: "10px 0" }}>
                                <div style={{ 
                                    width: "100px", 
                                    height: "100px", 
                                    borderRadius: "50%", 
                                    border: `8px solid ${riskScoreObj.color}`, 
                                    display: "flex", 
                                    alignItems: "center", 
                                    justifyContent: "center", 
                                    margin: "0 auto 10px",
                                    position: "relative",
                                    boxShadow: `0 0 30px ${riskScoreObj.color}40`
                                }}>
                                    <div>
                                        <div style={{ fontSize: "2rem", fontWeight: "bold", color: "white" }}>{riskScoreObj.score}</div>
                                        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>/ 100</div>
                                    </div>
                                </div>
                                <div style={{ fontSize: "1rem", color: riskScoreObj.color, fontWeight: "bold", textTransform: "uppercase" }}>
                                    {riskScoreObj.riskLevel} RISK
                                </div>
                            </div>
                        </div>

                        {/* 2. COMPREHENSIVE SECURITY CHECKLIST */}
                        <div className="analytics-card glass-card-hover" style={{ gridColumn: "span 2" }}>
                             <div className="card-header">
                                <span className="card-icon">🔐</span>
                                <h4>Compliance & Security Checklist</h4>
                            </div>
                            
                            <div className="security-grid-layout">
                                {/* Group 1: Registrar Security */}
                                <div className="security-group">
                                    <h5>🔐 Registrar Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.mfa} onChange={(e) => updateSecurityField('mfa', e.target.checked)} />
                                        <span>MFA Enabled</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.lock} onChange={(e) => updateSecurityField('lock', e.target.checked)} />
                                        <span>Registrar Lock</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.registrarLock} onChange={(e) => updateSecurityField('registrarLock', e.target.checked)} />
                                        <span>Registry Lock</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.autoRenew} onChange={(e) => updateManualField('autoRenew', e.target.checked)} />
                                        <span>Auto Renew</span>
                                    </label>
                                </div>

                                {/* Group 2: DNS Security */}
                                <div className="security-group">
                                    <h5>🌐 DNS Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dnssec} onChange={(e) => updateSecurityField('dnssec', e.target.checked)} />
                                        <span>DNSSEC</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.secureNameservers} onChange={(e) => updateSecurityField('secureNameservers', e.target.checked)} />
                                        <span>Secure Nameservers</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.noDanglingRecords} onChange={(e) => updateSecurityField('noDanglingRecords', e.target.checked)} />
                                        <span>No Dangling Records</span>
                                    </label>
                                </div>

                                {/* Group 3: Web Security */}
                                <div className="security-group">
                                    <h5>🔑 Web Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.tlsVersion} onChange={(e) => updateSecurityField('tlsVersion', e.target.checked)} />
                                        <span>TLS Version (v1.2+)</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.sslExpiry} onChange={(e) => updateSecurityField('sslExpiry', e.target.checked)} />
                                        <span>Valid SSL Expiry</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.hsts} onChange={(e) => updateSecurityField('hsts', e.target.checked)} />
                                        <span>HSTS Enabled</span>
                                    </label>
                                </div>

                                {/* Group 4: Email Security */}
                                <div className="security-group">
                                    <h5>📧 Email Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.spf} onChange={(e) => updateSecurityField('spf', e.target.checked)} />
                                        <span>SPF Record</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dkim} onChange={(e) => updateSecurityField('dkim', e.target.checked)} />
                                        <span>DKIM Record</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dmarc} onChange={(e) => updateSecurityField('dmarc', e.target.checked)} />
                                        <span>DMARC Record</span>
                                    </label>
                                </div>

                                {/* Group 5: Threat Monitoring */}
                                <div className="security-group">
                                    <h5>🛡️ Threat Monitoring</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.blacklistCheck} onChange={(e) => updateSecurityField('blacklistCheck', e.target.checked)} />
                                        <span>Blacklist Clear</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.phishingDetection} onChange={(e) => updateSecurityField('phishingDetection', e.target.checked)} />
                                        <span>Phishing Detected</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.typosquatting} onChange={(e) => updateSecurityField('typosquatting', e.target.checked)} />
                                        <span>No Typosquatting</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        {/* 3. AUDIT LOG */}
                        <div className="analytics-card glass-card-hover">
                             <div className="card-header">
                                <span className="card-icon">📝</span>
                                <h4>Audit & Workflow Log</h4>
                            </div>
                            <div style={{ maxHeight: "150px", overflowY: "auto", marginBottom: "10px" }}>
                                {currentManualData.notes.length > 0 ? currentManualData.notes.map((note, i) => (
                                    <div key={i} style={{ fontSize: "0.75rem", marginBottom: "8px", borderBottom: "1px dashed var(--border-color)", paddingBottom: "5px" }}>
                                        <div style={{ color: "var(--status-blue)", fontSize: "0.7rem" }}>{formatDate(note.date)}</div>
                                        <div>{note.text}</div>
                                    </div>
                                )) : <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>No notes yet.</div>}
                            </div>
                            <button onClick={addNote} className="up-btn-gray" style={{ fontSize: "0.7rem", width: "100%" }}>+ Add Note / Action</button>
                        </div>
                    </div>
                </div>
            )}

          </div>
        ) : (
          <div className="up-empty-state fade-in-content">
            <div style={{fontSize: "3rem", marginBottom: "20px"}}>🔍</div>
            <h3>Select a domain</h3>
            <p>Choose a domain from sidebar to view detailed analytics, asset management, and risk scoring.</p>
          </div>
        )}
      </main>
      
      {/* MODALS */}
      <DomainAddModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onAdd={handleAdd}
        isLoading={isAdding}
      />

      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Domain Report"
        username={username}
      />
      
      {/* NEW: PROFESSIONAL DELETE CONFIRMATION MODAL */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        onClose={() => setDeleteModal({ isOpen: false, id: null })}
        onConfirm={handleConfirmDelete}
        title="Delete Domain Asset"
        message="Are you sure you want to stop tracking this domain? This action cannot be undone and all historical data will be lost."
      />
    </div>
  );
};

// ================= MONITORING COMPONENT =================
const MonitoringComponent = ({ onBack, token, username }) => {
  // LocalStorage Keys
  const STORAGE_KEY_DATA = 'cyberguard_monitor_data';
  const STORAGE_KEY_URL = 'cyberguard_monitor_url';
  const STORAGE_KEY_STATE = 'cyberguard_monitor_state';

  // Initialize state from localStorage if available
  const [url, setUrl] = useState(() => {
    return localStorage.getItem(STORAGE_KEY_URL) || "";
  });
  
  const [lastStartedUrl, setLastStartedUrl] = useState("");
  
  const [isMonitoring, setIsMonitoring] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY_STATE);
    return stored ? JSON.parse(stored) : false;
  });

  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("monitoring");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  
  const [selectedMonitor, setSelectedMonitor] = useState(null);
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);

  // --- NEW: Success Modal State ---
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [newlyAddedUrl, setNewlyAddedUrl] = useState("");

  // Load data from localStorage on mount
  const [data, setData] = useState(() => {
    try {
      const storedData = localStorage.getItem(STORAGE_KEY_DATA);
      return storedData ? JSON.parse(storedData) : {
        targets: [],
        current_latencies: {},
        baseline_avgs: {},
        status_messages: {},
        histories: {},
        timestamps: {},
      };
    } catch (e) {
      return {
    targets: [],
    current_latencies: {},
    baseline_avgs: {},
    current_statuses: {},
    histories: {},
    timestamps: {},
};
    }
  });

  // Persist data to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(data));
    localStorage.setItem(STORAGE_KEY_URL, url);
    localStorage.setItem(STORAGE_KEY_STATE, JSON.stringify(isMonitoring));
  }, [data, url, isMonitoring]);

     const isTargetDown = (status, latency) => {
    if (!status) return false;
    const upperStatus = status.toUpperCase();
    const backendDown = 
           upperStatus.includes("CRITICAL") || 
           upperStatus.includes("ERROR") || 
           upperStatus.includes("SERVER DOWN") ||
           upperStatus.includes("CONNECTION REFUSED") ||
           upperStatus.includes("NOT FOUND") || 
           upperStatus.includes("TIMEOUT") ||
           upperStatus.includes("UNREACHABLE") ||
           latency === 0;           
    return backendDown;
  };

  useEffect(() => {
      const syncBackendState = async () => {
          try {
              const response = await fetch("http://localhost:8000/status", {
                  headers: { 'Authorization': `Bearer ${token}` }
              });
              if (response.ok) {
                  const backendData = await response.json();
                  
                  // Only overwrite local state if backend has active targets or we are actively monitoring
                  if (backendData.is_monitoring || (backendData.targets && backendData.targets.length > 0)) {
                      setIsMonitoring(backendData.is_monitoring);
                      setData(backendData); 
                      if (backendData.is_monitoring) {
                          const activeUrl = backendData.target_url || (backendData.targets.length > 0 ? backendData.targets[0] : "");
                          setUrl(activeUrl);
                          setLastStartedUrl(activeUrl);
                      }
                  }
              }
          } catch (error) {
              console.error("Failed to sync with backend:", error);
          }
      };
      syncBackendState();
  }, [token]);

  useEffect(() => {
    let interval;
    if (isMonitoring) {
      interval = setInterval(async () => {
        try {
          const response = await fetch("http://localhost:8000/status", {
              headers: { 'Authorization': `Bearer ${token}` }
          });
          if (response.status === 401) {
              clearInterval(interval);
              alert("Session expired");
              window.location.reload();
              return;
          }
          const jsonData = await response.json();
          
          if (!jsonData.is_monitoring && isMonitoring) {
              setIsMonitoring(false);
          } else {
              setData(jsonData);
          }
        } catch (error) {
          console.error("Backend connection lost", error);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isMonitoring, token]);

  const handleGlobalMonitoringReport = () => {
    setIsPwdModalOpen(true);
  };

  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch("http://localhost:8000/monitoring/global-report", {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password })
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.detail || "Failed to generate report");
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `global_session_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report: " + err.message);
    }
  };

  const handleStart = async () => {
    if (isMonitoring) return;
    if (!url || !url.startsWith("http")) {
      alert("Please enter a valid URL starting with http/https");
      return;
    }
    setIsLoading(true); 
    const payload = { url: url.trim() };
    try {
      const response = await fetch("http://localhost:8000/start", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json", 
          Accept: "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
          if (response.status === 401) {
              alert("Unauthorized");
              return;
          }
          const errorBody = await response.json().catch(() => ({ detail: "No details" }));
          throw new Error(`Backend rejected request (${response.status}): ${errorBody.detail || "Validation error"}`);
      }
      await response.json();
      
      // --- NEW: Trigger Success Modal ---
      setNewlyAddedUrl(payload.url);
      setShowSuccessModal(true);
      // -----------------------------------

      setIsMonitoring(true);
      setLastStartedUrl(url.trim()); 
    } catch (err) {
      console.error(err);
      alert("Start failed:\n" + (err.message || "Unknown error"));
    } finally {
      setIsLoading(false); 
    }
  };

  const handleResume = () => {
      if (!url || !url.startsWith("http")) {
          alert("Could not determine the target URL to resume. Please enter it manually.");
          return;
      }
      handleStart();           
  };

  const handleStop = async () => {
    try {
      const res = await fetch("http://localhost:8000/stop", { 
          method: "POST",
          headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error(res.statusText);
      setIsMonitoring(false);
    } catch (error) {
      console.error(error);
      alert("Failed to stop: " + error.message);
    }
  };

  // --- MODIFIED: Clear Logic to remove localStorage ---
  const handleClear = async () => {
    // 1. Call the backend to stop the monitoring loop
    await handleStop(); 

    // 2. Clear the local state
    setData({
      targets: [],
      current_latencies: {},
      baseline_avgs: {},
      status_messages: {},
      histories: {},
      timestamps: {},
    });
    setIsMonitoring(false);
    setSelectedMonitor(null);
    setLastStartedUrl(""); 
    
    // 3. Clear Persistence
    localStorage.removeItem(STORAGE_KEY_DATA);
    localStorage.removeItem(STORAGE_KEY_URL);
    localStorage.removeItem(STORAGE_KEY_STATE);
  };

  const getFilteredTargets = () => {
    return data.targets.filter((target) => {
      const matchesSearch = target.toLowerCase().includes(searchTerm.toLowerCase());
      const latency = data.current_latencies[target] || 0;
      const status = data.status_messages[target] || "";
      const down = isTargetDown(status, latency);
      
      let matchesFilter = true;
      if (filterStatus === "up") matchesFilter = !down;
      if (filterStatus === "down") matchesFilter = down;

      return matchesSearch && matchesFilter;
    });
  };

  // --- NEW: Success Modal Component ---
  const SuccessModal = ({ isOpen, onClose, targetUrl }) => {
      if (!isOpen) return null;
      
      return (
          <div className="modal-overlay" onClick={onClose}>
              <div className="success-modal-content" onClick={(e) => e.stopPropagation()}>
                  <div className="success-icon-circle">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                  </div>
                  <h3 className="success-title">Monitor Active</h3>
                  <p style={{color: "var(--text-muted)", marginBottom: "20px"}}>
                      The system is now tracking the health and latency of this endpoint in real-time.
                  </p>
                  
                  <div className="success-url">
                      {targetUrl}
                  </div>
                  
                  <button onClick={onClose} className="btn-success-close">
                      Got it
                  </button>
              </div>
          </div>
      );
  };

  const MonitorDetailView = ({ target }) => {
      const history = data.histories[target] || [];
      const status = data.current_statuses[target] || "Idle";
      
      const SLOW_THRESHOLD = 2000;
      const validHistory = history.filter(h => h > 0);
      const validCount = validHistory.length;
      const totalCount = history.length;
      const healthyCount = history.filter(h => h > 0 && h < SLOW_THRESHOLD).length;
      
      const uptimePercent = totalCount > 0 ? ((healthyCount / totalCount) * 100).toFixed(2) : "0.00";
      const avg = validHistory.length ? (validHistory.reduce((a, b) => a + b, 0) / validHistory.length).toFixed(0) : 0;
      const min = validHistory.length ? Math.min(...validHistory).toFixed(0) : 0;
      const max = validHistory.length ? Math.max(...validHistory).toFixed(0) : 0;
      
          const is404 = status.includes("NOT FOUND");
          const down = isTargetDown(status, history[history.length - 1]);
          const isSlow = !down && (status.includes("WARNING") || (history.length > 0 && history[history.length-1] > 2000));
          const lastCheck = new Date().toLocaleTimeString();

          const getDetailStatusLabel = () => {
            if (is404) return "404 Not Found";
            if (!down) return isSlow ? "SLOW RESPONSE" : "UP";
            const upperStatus = status.toUpperCase();
            if (upperStatus.includes("TIMEOUT")) return "TIMEOUT";
            if (upperStatus.includes("CRITICAL") || upperStatus.includes("PATTERN")) return "CRITICAL";
            if (upperStatus.includes("REFUSED")) return "UNREACHABLE";
            return "DOWN";
          };

          return (
              <div className="monitor-detail-container fade-in-content">
                  <button onClick={() => setSelectedMonitor(null)} className="back-btn" style={{marginBottom: "20px"}}>
                  ← Back to Dashboard
              </button>

              <div className="up-widget" style={{borderLeft: "5px solid", borderLeftColor: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                  <div style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                      <div>
                          <h1 style={{fontSize: "2rem", margin: "0 0 10px 0"}}>{target.replace(/^https?:\/\//, '')}</h1>
                          <div style={{display: "flex", alignItems: "center", gap: "20px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                                  {getDetailStatusLabel()}
                              </div>
                              <div style={{color: "var(--text-muted)", fontSize: "0.9rem"}}>
                                  HTTP/S monitor for {target}
                              </div>
                          </div>
                      </div>
                  </div>
                  <div style={{textAlign: "right", color: "var(--text-muted)", marginTop: "10px"}}>
                      <div>Last check: {lastCheck}</div>
                      <div>Checked every 1.5s</div>
                  </div>
              </div>

              <div className="analytics-grid" style={{marginTop: "20px"}}>
                  <div className="analytics-card glass-card-hover" style={{gridColumn: "span 3"}}>
                      <div className="card-header">
                          <span className="card-icon">⚡</span>
                          <h4>Response Time (Last Session)</h4>
                      </div>
                      <div style={{display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginTop: "10px"}}>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-blue)"}}>{avg} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Average</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-green)"}}>{min} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Minimum</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-red)"}}>{max} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Maximum</div>
                          </div>
                      </div>
                  </div>
              </div>

              <div className="analytics-grid" style={{marginTop: "20px", gridTemplateColumns: "repeat(4, 1fr)"}}>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Current Session</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 24h (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 30 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 365 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
              </div>

              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <div className="card-header">
                      <h4>Response Time History</h4>
                      <span className="text-muted" style={{fontSize: "0.8rem"}}>Last {history.length} checks</span>
                  </div>
                  <div style={{padding: "20px", display: "flex", justifyContent: "center"}}>
                       <Sparkline history={history} width={800} height={200} isDegraded={down} />
                  </div>
              </div>

              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <h4>Latest Incidents</h4>
                  {down ? (
                      <table style={{width: "100%", textAlign: "left", borderCollapse: "collapse", marginTop: "10px"}}>
                          <thead>
                              <tr style={{borderBottom: "1px solid rgba(255,255,255,0.1)"}}>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Status</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Root Cause</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Started</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Duration</th>
                              </tr>
                          </thead>
                          <tbody>
                              <tr>
                                  <td style={{padding: "10px", color: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : "var(--status-green)", fontWeight: "bold"}}>
                                      {is404 ? "404 Error" : "Down"}
                                  </td>
                                  <td style={{padding: "10px"}}>{status}</td>
                                  <td style={{padding: "10px"}}>{lastCheck}</td>
                                  <td style={{padding: "10px", color: "var(--status-red)"}}>Ongoing...</td>
                              </tr>
                          </tbody>
                      </table>
                  ) : isSlow ? (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-orange)"}}>⚠️ High latency detected. Site is responding but slowly.</p>
                      </div>
                  ) : (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-green)"}}>✅ No active incidents in the current session.</p>
                      </div>
                  )}
              </div>
          </div>
      );
  };

  const renderContent = () => {
    if (selectedMonitor) {
        return <MonitorDetailView target={selectedMonitor} />;
    }

    if (activeTab === "monitoring") {
      const displayTargets = getFilteredTargets();
      return (
        <div className="analytics-grid" style={{marginTop: "20px"}}>
          {displayTargets.length === 0 ? (
            <div className="up-empty-state" style={{gridColumn: "1 / -1"}}>
              <p>No monitors found matching your criteria.</p>
            </div>
          ) : (
            displayTargets.map((target) => {
              const history = data.histories[target] || [];
              let latency = data.current_latencies[target] || 0;
              if (latency === 0 && history.length > 0) {
                  latency = history[history.length - 1];
              }

              const status = data.status_messages[target] || "Idle";
              const down = isTargetDown(status, latency);
              
              const is404 = status.includes("NOT FOUND");
              const isSlow = !down && (status.includes("WARNING") || latency > 2000);

              let statusLabel = "Operational";
              let statusColorClass = "status-green";
              let statusBadgeColor = "var(--status-green)";
              let statusBgColor = "rgba(16, 185, 129, 0.15)";

              if (is404) {
                  statusLabel = "404 Not Found";
                  statusColorClass = "status-red";
                  statusBadgeColor = "var(--status-red)";
                  statusBgColor = "rgba(239, 68, 68, 0.15)";
             } else if (down) {
              const upperStatus = status.toUpperCase();
              if (upperStatus.includes("TIMEOUT")) {
                statusLabel = "TIMEOUT";
              } else if (upperStatus.includes("CRITICAL") || upperStatus.includes("PATTERN")) {
                statusLabel = "CRITICAL";
              } else if (upperStatus.includes("REFUSED")) {
                statusLabel = "UNREACHABLE";
              } else {
                statusLabel = "DOWN";
              }
              statusColorClass = "status-red";
              statusBadgeColor = "var(--status-red)";
              statusBgColor = "rgba(239, 68, 68, 0.15)";
              } else {
                  if (isSlow) {
                      statusLabel = "SLOW RESPONSE";
                      statusColorClass = "status-slow";
                      statusBadgeColor = "var(--status-orange)";
                      statusBgColor = "rgba(245, 158, 11, 0.15)";
                  } else if (status.includes("Learning")) {
                      statusLabel = "Learning Baseline";
                      statusColorClass = "status-slow";
                      statusBadgeColor = "var(--status-blue)";
                      statusBgColor = "rgba(6, 182, 212, 0.15)";
                  } else if (status.includes("Unstable")) {
                      statusLabel = "Unstable";
                      statusColorClass = "status-slow";
                      statusBadgeColor = "var(--status-orange)";
                      statusBgColor = "rgba(245, 158, 11, 0.15)";
                  }
              }

              return (
                <div 
                  key={target} 
                  className="analytics-card glass-card-hover" 
                  onClick={() => setSelectedMonitor(target)} 
                  style={{cursor: "pointer", position: "relative", overflow: "hidden"}}
                >
                    <div style={{
                        position: "absolute", top: 0, left: 0, bottom: 0, width: "4px", 
                        background: statusBadgeColor
                    }}></div>

                    <div className="monitor-card-header" style={{paddingLeft: "12px"}}>
                        <div className="monitor-card-title">
                            <span style={{fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px"}}>Endpoint</span>
                            <span className="monitor-card-url" title={target}>
                                {target.replace(/^https?:\/\//, '')}
                            </span>
                        </div>
                        
                        <div className="up-status-badge" style={{
                            background: statusBgColor,
                            borderColor: statusBadgeColor,
                            color: statusBadgeColor,
                            fontSize: "0.65rem",
                            padding: "4px 8px",
                            whiteSpace: "nowrap"
                        }}>
                            {statusLabel}
                        </div>
                    </div>

                    <div className="monitor-chart-wrapper">
                        <Sparkline history={history} width={400} height={70} isDegraded={down} />
                    </div>

                    <div className="card-body" style={{paddingTop: "5px", paddingLeft: "12px", paddingRight: "12px", paddingBottom: "15px"}}>
                        <div className="monitor-card-metrics">
                            <div className="metric-box">
                                <span className="metric-label">Latency</span>
                                <span className="metric-value" style={{color: latency > 1000 ? "var(--status-orange)" : "white"}}>
                                    {latency.toFixed(0)} <span style={{fontSize: "0.8rem", color: "var(--text-muted)"}}>ms</span>
                                </span>
                            </div>
                            <div className="metric-box" style={{textAlign: "right"}}>
                                <span className="metric-label">Last Check</span>
                                <span style={{fontSize: "0.9rem", color: "var(--text-main)", fontWeight: "600"}}>
                                    {new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
              );
            })
          )}
        </div>
      );
    } else if (activeTab === "incidents") {
      const incidents = data.targets.filter(t => {
           const latency = data.current_latencies[t] || 0;
           return isTargetDown(data.status_messages[t], latency);
      });

      return (
        <div className="up-monitors-list">
          {incidents.length === 0 ? (
            <div className="up-empty-state" style={{borderColor: "var(--status-blue)"}}>
              <p>Great! No incidents detected.</p>
            </div>
          ) : (
            <>
              <div className="up-widget" style={{marginBottom: "20px", borderLeft: "4px solid var(--status-red)"}}>
                <h4 style={{color: "white", marginBottom: "5px"}}>Active Incidents</h4>
                <p style={{fontSize: "0.9rem", color: "var(--text-muted)"}}>
                  {incidents.length} monitor(s) are currently reporting issues.
                </p>
              </div>
              {incidents.map((target) => {
                const status = data.status_messages[target];
                const latency = data.current_latencies[target] || 0;
                const is404 = status && status.includes("NOT FOUND");
                
                return (
                  <div key={target} className={`up-monitor-row down ${is404 ? 'row-404' : ''}`}>
                    <div className="up-status-icon">
                      <div className={`indicator ${is404 ? "red" : "red"}`}></div>
                    </div>
                    <div className="up-monitor-info">
                      <div className="up-url">{target}</div>
                      <div className="up-type" style={{color: is404 ? "var(--status-red)" : "var(--status-red)"}}>
                          {is404 ? "404 Page Not Found" : (latency > 3000 ? `CRITICAL LAG (${latency.toFixed(0)}ms)` : status)}
                      </div>
                    </div>
                    <div className="up-monitor-uptime">
                      <span className="time-ago">Ongoing</span>
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      );
    }
  };

  const getOverallUptime = () => {
      let totalChecks = 0;
      let upChecks = 0;

      Object.values(data.histories).forEach(history => {
          totalChecks += history.length;
          upChecks += history.filter(h => h > 0).length;
      });

      if (totalChecks === 0) return "N/A";
      return ((upChecks / totalChecks) * 100).toFixed(2) + "%";
  };

  return (
    <div className="up-dashboard">
      <aside className="up-sidebar">
        <div className="up-sidebar-header">
          <h2>CyberGuard</h2>
          <div className={`up-status-badge ${isMonitoring ? "live" : "idle"}`}>
            {isMonitoring ? "● System Active" : "○ System Idle"}
          </div>
        </div>

        <nav className="up-nav">
          <div 
            className={`nav-item ${activeTab === "monitoring" ? "active" : ""}`}
            onClick={() => { setActiveTab("monitoring"); setSelectedMonitor(null); }}
          >
            Monitoring
          </div>
          <div 
            className={`nav-item ${activeTab === "incidents" ? "active" : ""}`}
            onClick={() => setActiveTab("incidents")}
          >
            Incidents
          </div>
        </nav>

     <div className="up-add-monitor">
        <label>Add New Monitor</label>
        <div className="up-input-group">
         <input 
            type="text" 
            value={url} 
            onChange={(e) => setUrl(e.target.value)} 
            disabled={isMonitoring || isLoading} 
            placeholder="https://example.com"
            autoComplete="off"
          />
        
        {!isMonitoring ? (
          <>
              {data.targets.length > 0 ? (
                   <button className="up-btn-resume" onClick={handleResume} disabled={isLoading}>Resume Monitoring</button>
              ) : (
                  <button className="up-btn-green" onClick={handleStart} disabled={isLoading || !url}>
                      {isLoading ? "Starting..." : "Start Monitoring"}
                  </button>
              )}
              <button className="up-btn-gray" onClick={handleClear}>Clear</button>
          </>
        ) : (
            <button className="up-btn-red" onClick={handleStop}>Stop</button>
        )}
    </div>
</div>
      </aside>

      <main className="up-main">
        <header className="up-header">
          <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
              <h3 style={{textTransform: "capitalize", margin: 0}}>{selectedMonitor ? "Monitor Details" : activeTab.replace("_", " ")}</h3>
              {!selectedMonitor && activeTab === "monitoring" && (
                  <span style={{fontSize: "0.8rem", color: "var(--text-muted)"}}>({data.targets.length})</span>
              )}
          </div>
          
          <div className="up-actions">
            {!selectedMonitor && activeTab === "monitoring" && data.targets.length > 0 && (
                <button onClick={handleGlobalMonitoringReport} className="up-btn-blue" style={{marginRight: "10px"}}>
                    📊 Global Report
                </button>
            )}

            {activeTab === "monitoring" && !selectedMonitor && (
              <>
                <input 
                  type="text" 
                  placeholder="Search monitors..." 
                  className="up-search" 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  autoComplete="off"
                />
                <div style={{ position: "relative" }}>
                  <button 
                    className="up-filter-btn" 
                    onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                  >
                    {filterStatus === "all" ? "Filter" : filterStatus} ▼
                  </button>
                  {showFilterDropdown && (
                    <div style={{
                      position: "absolute", top: "100%", right: 0, marginTop: "5px", 
                      background: "var(--bg-panel)", border: "1px solid var(--border-color)", 
                      borderRadius: "6px", width: "120px", boxShadow: "0 4px 12px rgba(0,0,0,0.8)",
                      zIndex: 9999, color: "var(--text-main)"
                    }}>
                      <div onClick={() => { setFilterStatus("all"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "all" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>All</div>
                      <div onClick={() => { setFilterStatus("up"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "up" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Up</div>
                      <div onClick={() => { setFilterStatus("down"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "down" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Down</div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </header>

        {renderContent()}
      </main>

      {activeTab === "monitoring" && !selectedMonitor && (
        <aside className="up-right-panel">
          <div className="up-widget current-status">
            <h4>Current status</h4>
            <div className="status-grid">
              {(() => {
                  let down = 0;
                  let up = 0;
                  data.targets.forEach(t => {
    if(isTargetDown(data.current_statuses[t], data.current_latencies[t])) down++;
    else up++;
});
                  return (
                      <>
                          <div className="status-item">
                              <span className="label">Down</span>
                              <span className="val red">{down}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Up</span>
                              <span className="val green">{up}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Paused</span>
                              <span className="val gray">{0}</span>
                          </div>
                      </>
                  )
              })()}
            </div>
          </div>

          <div className="up-widget last-hours">
            <h4>Last 24 hours</h4>
            <div className="stat-row">
              <span className="lbl">Overall uptime</span>
              <span className="val">{getOverallUptime()}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Incidents</span>
              <span className="val">{data.targets.filter(t => isTargetDown(data.status_messages[t], data.current_latencies[t])).length}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Without incid.</span>
              <span className="val">{data.targets.filter(t => isTargetDown(data.current_statuses[t], data.current_latencies[t])).length}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Affected mon.</span>
              <span className="val">{data.targets.filter(t => isTargetDown(data.status_messages[t], data.current_latencies[t])).length}</span>
            </div>
          </div>
          
          <div className="up-footer-nav">
            <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
          </div>
        </aside>
      )}

      {/* PASSWORD MODAL */}
      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Monitoring Report"
        username={username}
      />

      {/* SUCCESS MODAL */}
      <SuccessModal 
        isOpen={showSuccessModal} 
        onClose={() => setShowSuccessModal(false)}
        targetUrl={newlyAddedUrl}
      />
    </div>
  );
};

// ================= LANDING PAGE COMPONENT =================
const LandingPage = ({ onLogin, onRegister }) => {
  const scrollToSection = (id) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="landing-page">
      <div className="glow-orb orb-1"></div>
      <div className="glow-orb orb-2"></div>

      <nav className="landing-nav">
        <div className="brand">
          Cyber<span>Guard</span>
        </div>
        <div className="nav-actions">
          <a 
            href="#contact" 
            onClick={(e) => { e.preventDefault(); scrollToSection('contact'); }} 
            className="btn-nav contact"
          >
            Contact Us
          </a>
          <button onClick={onLogin} className="btn-nav login">
            Login
          </button>
          <button onClick={onRegister} className="btn-nav register">
            Register
          </button>
        </div>
      </nav>

      <header className="hero-section">
        <h1 className="hero-title">
          Next-Generation Domain
          <br /> Monitoring & Detection
        </h1>
        <p className="hero-subtitle">
          Unify automated domain intelligence with manual asset governance. Secure your infrastructure with  
          real-time anomaly detection and comprehensive risk reporting.
        </p>
        <div className="cta-group">
            <button 
                onClick={() => scrollToSection('features')} 
                className="btn-large btn-secondary-large" 
                style={{ 
                    background: 'transparent', 
                    border: '1px solid var(--status-blue)',
                    color: 'var(--status-blue)',
                    padding: '16px 48px',
                    fontSize: '1.1rem',
                    fontWeight: '700',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                    letterSpacing: '1px',
                    borderRadius: '2px',
                    transition: '0.2s'
                }}
                onMouseEnter={(e) => {
                    e.target.style.background = 'rgba(6, 182, 212, 0.1)';
                    e.target.style.color = 'white';
                }}
                onMouseLeave={(e) => {
                    e.target.style.background = 'transparent';
                    e.target.style.color = 'var(--status-blue)';
                }}
            >
                Learn More
            </button>
        </div>
      </header>

      <section id="features" className="features-section">
        <div className="section-header">
          <h2>System Capabilities</h2>
          <p>Everything you need to manage your digital presence.</p>
        </div>
        <div className="cards-grid">
          <div className="feature-card">
            <div className="card-icon">📡</div>
            <h3>Auto-Tracking</h3>
            <p>
              Automatically tracks your domain's status, DNS records, and registration information.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">📝</div>
            <h3>Manual Asset Mgmt</h3>
            <p>
              Allows you to manually enter ownership details and infrastructure information.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">📊</div>
            <h3>Risk Intelligence</h3>
            <p>
              Calculates a risk score based on expiration dates and security checklist status.
            </p>
          </div>
          
          <div className="feature-card">
            <div className="card-icon">⚡</div>
            <h3>Real-Time Monitoring</h3>
            <p>
              Continuously checks if your website is online and measures its response speed.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">🔒</div>
            <h3>Secure Reports</h3>
            <p>
              Generates password-protected PDF reports for your records and compliance needs.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">🚨</div>
            <h3>Incident Response</h3>
            <p>
              Logs downtime incidents and sends alerts when services go down.
            </p>
          </div>
        </div>
      </section>

      <section id="contact" className="contact-section">
        <div className="section-header">
          <h2>Contact Our Developers</h2>
          <p>Connect with the architects behind your digital defense.</p>
        </div>
        <div className="team-grid">
          <div className="team-card">
            <div className="avatar">HC</div>
            <div className="dev-name">Henon Chare</div>
           
            <a href="mailto:henonchare21@gmail.com" className="contact-link email-link">📧 henonchare21@gmail.com</a>
            <a href="tel:+251982049520" className="contact-link phone-link">📞 +251 98 204 9520</a>
            <a href="https://github.com/henon-chare" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 henon-chare</a>
          </div>
          <div className="team-card">
            <div className="avatar">BT</div>
            <div className="dev-name">Biniyam Temesgen</div>
            
            <a href="mailto:biniyamtemesgen40@gmail.com" className="contact-link email-link">📧 biniyamtemesgen40@gmail.com</a>
            <a href="tel:+251985957185" className="contact-link phone-link">📞 +251 98 595 7185</a>
            <a href="https://github.com/Bi-ni-yam" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 Bi-ni-yam</a>
          </div>
          <div className="team-card">
            <div className="avatar">MK</div>
            <div className="dev-name">Mikiyas Kindie</div>
            
            <a href="mailto:mikiyaskindie6@gmail.com" className="contact-link email-link">📧 mikiyaskindie6@gmail.com</a>
            <a href="tel:+251948010770" className="contact-link phone-link">📞 +251 94 801 0770</a>
            <a href="https://github.com/mikii122129" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 mikii122129</a>
          </div>
          <div className="team-card">
            <div className="avatar">AM</div>
            <div className="dev-name">Abinet Melkamu</div>
           
            <a href="mailto:instaman2124@gmail.com" className="contact-link email-link">📧 instaman2124@gmail.com</a>
            <a href="tel:+251923248825" className="contact-link phone-link">📞 +251 92 324 8825</a>
            <a href="https://github.com/abinetbdu" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 abinetbdu</a>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        &copy; 2026 Domain Monitoring and Detecting System. All rights reserved.
      </footer>
    </div>
  );
};

// ================= MAIN APP COMPONENT =================
function App() {
  
const ToastContainer = () => {
    const [toasts, setToasts] = useState([]);

    useEffect(() => {
        window.showToast = (message, type = "info") => {
            const id = Date.now();
            setToasts(prev => [...prev, { id, message, type }]);
            setTimeout(() => {
                setToasts(prev => prev.filter(t => t.id !== id));
            }, 4000);
        };
    }, []);

    return (
        <div className="toast-container">
            {toasts.map(toast => (
                <div key={toast.id} className={`toast ${toast.type}`}>
                    <div className="toast-icon">
                        {toast.type === 'success' ? '✅' : toast.type === 'error' ? '❌' : 'ℹ️'}
                    </div>
                    <div>{toast.message}</div>
                </div>
            ))}
        </div>
    );
};
  const [showLanding, setShowLanding] = useState(true);
  const [page, setPage] = useState("login");
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    token: "",
  });
 // ... existing code ...
  const [message, setMessage] = useState("");
  const [userLoggedIn, setUserLoggedIn] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState(""); 

  const [authToken, setAuthToken] = useState(null); 
  const [selectedCard, setSelectedCard] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  
  // --- EXISTING STATE ---
  const [showPassword, setShowPassword] = useState(false);
  
  // --- NEW STATE: Independent visibility for Confirm Password ---
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const profileRef = useRef(null);
// ... existing code ...

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    const path = window.location.pathname;
    if (path.startsWith("/reset-password/")) {
      const tokenFromUrl = path.split("/")[2];
      if (tokenFromUrl) {
        setFormData(prev => ({ ...prev, token: tokenFromUrl }));
        setPage("reset");
        setShowLanding(false);
      }
    }
  }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    if (page === "register" || page === "reset") {
      if (formData.password !== confirmPassword) {
        setMessage("Passwords do not match.");
        return;
      }
    }
    
    // SPECIFIC LOGIC FOR FORGOT PASSWORD BUTTON
    // Disable the button immediately when user clicks "Send Reset Email"
    if (page === "forgot") {
        setIsSubmitting(true);
    }

    let url = "";
    let body = {};
    if (page === "login") {
      url = "http://localhost:8000/login";
      body = { username: formData.username, password: formData.password };
    } else if (page === "register") {
      url = "http://localhost:8000/register";
      body = { username: formData.username, email: formData.email, password: formData.password };
    } else if (page === "forgot") {
      url = "http://localhost:8000/forgot-password";
      body = { email: formData.email };
    } else if (page === "reset") {
      url = "http://localhost:8000/reset-password";
      body = { token: formData.token, new_password: formData.password, username: formData.username };
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setMessage(data.message);
        if (page === "login") {
          if (data.access_token) {
            setAuthToken(data.access_token);
            localStorage.setItem('auth_token', data.access_token);
          }
          setUserLoggedIn(true);
          setSelectedCard(null);
          setShowLanding(false);
        } else if (page === "register") {
          setTimeout(() => { setPage("login"); setMessage("Registration successful! Please login."); }, 1500);
        } else if (page === "reset") {
          setTimeout(() => { setPage("login"); setMessage("Password reset successful! Please login."); }, 2000);
        }
        // NOTE: For "forgot" page, we leave isSubmitting as true.
        // The button stays disabled and displays "Sending..." while the success message is shown.
        // The user sees the success message and the flow effectively ends for that action.
      } else {
        // On error, we re-enable the button so the user can try again.
        setIsSubmitting(false);
        
        let errorMessage = "Error occurred";
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            errorMessage = data.detail.map((err) => err.msg).join(", ");
          } else {
            errorMessage = data.detail;
          }
        } else {
          errorMessage = JSON.stringify(data);
        }
        setMessage(errorMessage);
      }
    } catch (err) {
      // On network error, re-enable the button.
      setIsSubmitting(false);
      setMessage("Server not reachable");
    }
  };

  // --- NEW LOGOUT HANDLER ---
  const handleLogout = () => {
     setUserLoggedIn(false); 
     setShowLanding(true);
     setAuthToken(null);
     localStorage.removeItem('auth_token');
     
     // Clear Monitoring Data on Logout
     localStorage.removeItem('cyberguard_monitor_data');
     localStorage.removeItem('cyberguard_monitor_url');
     localStorage.removeItem('cyberguard_monitor_state');
     
     setIsProfileOpen(false);
  };

  const HomePage = () => {
    if (selectedCard === "monitoring") {
      return <MonitoringComponent onBack={() => setSelectedCard(null)} token={authToken} username={formData.username} />;
    }
    if (selectedCard === "domains") {
      return <DomainTrackingComponent onBack={() => setSelectedCard(null)} token={authToken} username={formData.username} />;
    }
    if (selectedCard === "alerts") {
      return <AlertDashboardComponent onBack={() => setSelectedCard(null)} token={authToken} />;
    }
    return (
      <div className="dashboard">
        <header className="dashboard-header">
          <h1>CyberGuard</h1>
          
          <div className="profile-wrapper" ref={profileRef}>
            <div className="profile-trigger" onClick={() => setIsProfileOpen(!isProfileOpen)}>
                <div className="profile-icon-circle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                </div>
                <span className="profile-label">Profile</span>
                <span className="chevron">▼</span>
            </div>

            {isProfileOpen && (
                <div className="profile-dropdown">
                    <div className="profile-header">
                        <div className="avatar-large">
                           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                <circle cx="12" cy="7" r="4"></circle>
                            </svg>
                        </div>
                        <div className="user-info">
                            <h3>{formData.username || "User"}</h3>
                            <p>{formData.email || formData.username || "user@cyberguard.ai"}</p>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    <div className="profile-stats">
                        <div className="stat-item">
                            <span className="stat-label">Status</span>
                            <span className="stat-value text-green">Active</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-label">Role</span>
                            <span className="stat-value">Admin</span>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    {/* UPDATED: Use handleLogout */}
                    <button className="profile-logout-btn" onClick={handleLogout}>
                        Logout
                    </button>
                </div>
            )}
          </div>
        </header>
        <section className="hero">
          <h2>Security Operations Center</h2>
          <p>Monitor • Detect • Protect • Respond</p>
        </section>
        <section className="cards">
          <div className="card" onClick={() => setSelectedCard("monitoring")}>
            <span className="icon">🌐</span>
            <h3>Website Monitoring</h3>
            <p>Track uptime, response time, and anomalies in real time.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("domains")}>
            <span className="icon">🔍</span>
            <h3>Domain Tracking</h3>
            <p>Deep DNS inspection, WHOIS analysis, and domain reputation.</p>
          </div>
          <div className="card">
            <span className="icon">🛡️</span>
            <h3>Threat Detection</h3>
            <p>Identify vulnerabilities and suspicious activities.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("alerts")}>
            <span className="icon">🚨</span>
            <h3>Alert Dashboard</h3>
            <p>Instant alerts for critical security events.</p>
          </div>
        </section>
      </div>
    );
  };

  if (showLanding) return <LandingPage 
    onLogin={() => { setShowLanding(false); setPage("login"); }} 
    onRegister={() => { setShowLanding(false); setPage("register"); }} 
  />;

  if (userLoggedIn) return (
      <>
        <HomePage />
        <ToastContainer />
      </>
  );

  return (
    <div className="app-auth">
      <div className="container">
        <h1>CyberGuard</h1>
        <div style={{ marginBottom: "20px", color: "#94a3b8", cursor: "pointer", textDecoration: "underline" }} onClick={() => setShowLanding(true)}>
          &larr; Back to Home
        </div>
        {message && <div className="message">{message}</div>}
        <form onSubmit={handleSubmit} className="form" autoComplete="off">
          {(page === "register" || page === "login") && (
            <input 
              type="text" 
              name="username" 
              placeholder="Username" 
              value={formData.username} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
          {(page === "register" || page === "forgot") && (
            <input 
              type="email" 
              name="email" 
              placeholder="Email" 
              value={formData.email} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
                    {/* ... Password Field (Leave this one as is) ... */}
          {(page === "login" || page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                type={showPassword ? "text" : "password"} 
                name="password" 
                placeholder={page === "reset" ? "New Password" : "Password"} 
                value={formData.password} 
                onChange={handleChange} 
                required 
                autoComplete="new-password" 
              />
              <span className="eye-icon" onClick={() => setShowPassword(!showPassword)} role="button" tabIndex="0">{showPassword ? "🔐" : "🔓"}</span>
            </div>
          )}

          {/* ... Confirm Password Field (Updated below) ... */}
          {(page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                // CHANGED: Use showConfirmPassword here
                type={showConfirmPassword ? "text" : "password"} 
                name="confirmPassword" 
                placeholder="Confirm Password" 
                value={confirmPassword} 
                onChange={(e) => setConfirmPassword(e.target.value)} 
                required 
                autoComplete="new-password" 
              />
              {/* CHANGED: Toggle showConfirmPassword here */}
              <span className="eye-icon" onClick={() => setShowConfirmPassword(!showConfirmPassword)} role="button" tabIndex="0">
                {showConfirmPassword ? "🔐" : "🔓"}
              </span>
            </div>
          )}
          {page === "reset" && (
            <>
              <input type="text" name="username" placeholder="Username" value={formData.username} onChange={handleChange} required autoComplete="off" />
              <input type="text" name="token" placeholder="Reset Token (Check Email)" value={formData.token} onChange={handleChange} required autoComplete="off" />
            </>
          )}
          <button 
              type="submit" 
              disabled={page === "forgot" && isSubmitting}
              style={{ opacity: (page === "forgot" && isSubmitting) ? 0.6 : 1, cursor: (page === "forgot" && isSubmitting) ? 'not-allowed' : 'pointer' }}
          >
            {page === "login" && "Login"}
            {page === "register" && "Register"}
            {page === "forgot" && (isSubmitting ? "Sending..." : "Send Reset Email")}
            {page === "reset" && "Reset Password"}
          </button>
        </form>
        <div className="links">
          {page !== "login" && <p onClick={() => { setPage("login"); setMessage(""); setConfirmPassword(""); }}>Login</p>}
          {page !== "register" && <p onClick={() => { setPage("register"); setMessage(""); setConfirmPassword(""); }}>Register</p>}
          {page !== "forgot" && <p onClick={() => { setPage("forgot"); setMessage(""); setConfirmPassword(""); }}>Forgot-Password</p>}
          {page !== "reset" && page === "forgot" && <p onClick={() => { setPage("reset"); setMessage(""); setConfirmPassword(""); }}>Reset-Password</p>}
        </div>
      </div>
    </div>
  );
}

export default App;