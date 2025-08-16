/**
 * React Application for Enterprise CMDB Compliance Tool
 * Modern React components with hooks and real-time updates
 */

// React hooks and utilities
const { useState, useEffect, useCallback, useMemo } = React;

// Main App Component
const App = () => {
    const [currentView, setCurrentView] = useState('dashboard');
    const [findings, setFindings] = useState([]);
    const [scanProgress, setScanProgress] = useState(null);
    const [policies, setPolicies] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [websocket, setWebsocket] = useState(null);

    // WebSocket connection for real-time updates
    useEffect(() => {
        const ws = new WebSocket(`ws://${window.location.host}/ws/scan-updates`);
        
        ws.onopen = () => {
            console.log('WebSocket connected');
            setWebsocket(ws);
        };
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'scan_progress') {
                setScanProgress(data);
            } else if (data.type === 'scan_completed') {
                setScanProgress(null);
                fetchFindings(); // Refresh findings after scan completion
                showNotification('Scan completed successfully', 'success');
            }
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            setWebsocket(null);
        };
        
        return () => {
            ws.close();
        };
    }, []);

    // Fetch compliance findings
    const fetchFindings = useCallback(async (filters = {}) => {
        setLoading(true);
        setError(null);
        
        try {
            const params = new URLSearchParams();
            if (filters.business_unit) params.append('business_unit', filters.business_unit);
            if (filters.status) params.append('status', filters.status);
            
            const response = await fetch(`/api/v1/compliance/findings?${params}`, {
                headers: {
                    'Authorization': 'Bearer demo-token'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            setFindings(data);
        } catch (err) {
            setError(`Failed to fetch findings: ${err.message}`);
            console.error('Error fetching findings:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    // Fetch policies
    const fetchPolicies = useCallback(async () => {
        try {
            const response = await fetch('/api/v1/policies', {
                headers: {
                    'Authorization': 'Bearer demo-token'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            setPolicies(data);
        } catch (err) {
            console.error('Error fetching policies:', err);
        }
    }, []);

    // Start compliance scan
    const startScan = useCallback(async (scanConfig) => {
        setLoading(true);
        setError(null);
        
        try {
            const response = await fetch('/api/v1/compliance/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer demo-token'
                },
                body: JSON.stringify(scanConfig)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            showNotification(`Scan started: ${data.scan_id}`, 'info');
            
            // Initial scan progress
            setScanProgress({
                scan_id: data.scan_id,
                status: 'running',
                progress: 0,
                completed: 0,
                total: scanConfig.target_ips.length
            });
            
        } catch (err) {
            setError(`Failed to start scan: ${err.message}`);
            console.error('Error starting scan:', err);
        } finally {
            setLoading(false);
        }
    }, []);

    // Show notification
    const showNotification = (message, type = 'info') => {
        // Simple notification system (could be enhanced with toast library)
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 4px;
            color: white;
            font-weight: 500;
            z-index: 1000;
            animation: slideIn 0.3s ease;
            background-color: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 4000);
    };

    // Initialize data
    useEffect(() => {
        fetchFindings();
        fetchPolicies();
    }, [fetchFindings, fetchPolicies]);

    // Render different views
    const renderContent = () => {
        switch (currentView) {
            case 'dashboard':
                return <Dashboard 
                    findings={findings} 
                    scanProgress={scanProgress} 
                    onStartScan={startScan}
                    loading={loading}
                />;
            case 'findings':
                return <FindingsView 
                    findings={findings} 
                    onRefresh={fetchFindings}
                    loading={loading}
                />;
            case 'policies':
                return <PoliciesView 
                    policies={policies} 
                    onRefresh={fetchPolicies}
                />;
            case 'scan':
                return <ScanView 
                    onStartScan={startScan}
                    scanProgress={scanProgress}
                    loading={loading}
                />;
            default:
                return <Dashboard 
                    findings={findings} 
                    scanProgress={scanProgress} 
                    onStartScan={startScan}
                    loading={loading}
                />;
        }
    };

    return (
        <div className="app">
            <Header currentView={currentView} onViewChange={setCurrentView} />
            
            {error && (
                <div className="error-banner">
                    <span className="error-text">⚠️ {error}</span>
                    <button onClick={() => setError(null)} className="error-close">×</button>
                </div>
            )}
            
            <main className="main-content">
                {renderContent()}
            </main>
            
            <Footer />
        </div>
    );
};

// Header Component
const Header = ({ currentView, onViewChange }) => {
    const navItems = [
        { id: 'dashboard', label: '📊 Dashboard', icon: '📊' },
        { id: 'findings', label: '🔍 Findings', icon: '🔍' },
        { id: 'policies', label: '⚖️ Policies', icon: '⚖️' },
        { id: 'scan', label: '🔧 Scan', icon: '🔧' }
    ];

    return (
        <header className="header">
            <div className="header-content">
                <div className="logo">
                    <h1>🏢 CMDB Compliance</h1>
                    <span className="subtitle">Enterprise Monitoring</span>
                </div>
                
                <nav className="nav">
                    {navItems.map(item => (
                        <button
                            key={item.id}
                            className={`nav-item ${currentView === item.id ? 'active' : ''}`}
                            onClick={() => onViewChange(item.id)}
                        >
                            <span className="nav-icon">{item.icon}</span>
                            <span className="nav-label">{item.label}</span>
                        </button>
                    ))}
                </nav>
                
                <div className="header-actions">
                    <div className="status-indicator">
                        <div className="status-dot status-online"></div>
                        <span>Online</span>
                    </div>
                </div>
            </div>
        </header>
    );
};

// Dashboard Component
const Dashboard = ({ findings, scanProgress, onStartScan, loading }) => {
    // Calculate statistics
    const stats = useMemo(() => {
        const total = findings.length;
        const compliant = findings.filter(f => f.status === 'pass').length;
        const warnings = findings.filter(f => f.status === 'warn').length;
        const failures = findings.filter(f => f.status === 'fail').length;
        const unknown = findings.filter(f => f.status === 'unknown').length;
        
        const complianceScore = total > 0 ? Math.round((compliant / total) * 100) : 0;
        const avgRiskScore = total > 0 ? Math.round(
            findings.reduce((sum, f) => sum + f.risk_score, 0) / total
        ) : 0;
        
        return { total, compliant, warnings, failures, unknown, complianceScore, avgRiskScore };
    }, [findings]);

    const quickScan = () => {
        onStartScan({
            target_ips: ['10.1.1.10', '10.1.2.20', '10.1.3.30'],
            business_unit: null,
            scan_types: ['ssh', 'winrm', 'snmp'],
            priority: 'normal'
        });
    };

    return (
        <div className="dashboard">
            <div className="dashboard-header">
                <h2>Compliance Dashboard</h2>
                <div className="dashboard-actions">
                    <button 
                        onClick={quickScan} 
                        className="btn btn-primary"
                        disabled={loading}
                    >
                        🔍 Quick Scan
                    </button>
                </div>
            </div>

            {/* Statistics Cards */}
            <div className="stats-grid">
                <div className="stat-card stat-primary">
                    <div className="stat-icon">📊</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.complianceScore}%</div>
                        <div className="stat-label">Compliance Score</div>
                    </div>
                </div>
                
                <div className="stat-card stat-success">
                    <div className="stat-icon">✅</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.compliant}</div>
                        <div className="stat-label">Compliant Systems</div>
                    </div>
                </div>
                
                <div className="stat-card stat-warning">
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.warnings}</div>
                        <div className="stat-label">Warnings</div>
                    </div>
                </div>
                
                <div className="stat-card stat-danger">
                    <div className="stat-icon">❌</div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.failures}</div>
                        <div className="stat-label">Critical Issues</div>
                    </div>
                </div>
            </div>

            {/* Scan Progress */}
            {scanProgress && (
                <div className="scan-progress-card">
                    <h3>🔍 Active Scan Progress</h3>
                    <div className="progress-info">
                        <span>Scan ID: {scanProgress.scan_id}</span>
                        <span>Status: {scanProgress.status}</span>
                        <span>{scanProgress.completed}/{scanProgress.total} completed</span>
                    </div>
                    <div className="progress-bar">
                        <div 
                            className="progress-fill" 
                            style={{ width: `${scanProgress.progress || 0}%` }}
                        ></div>
                    </div>
                    <div className="progress-percentage">{Math.round(scanProgress.progress || 0)}%</div>
                </div>
            )}

            {/* Recent Findings */}
            <div className="recent-findings">
                <h3>Recent Findings</h3>
                <div className="findings-table-container">
                    <table className="findings-table">
                        <thead>
                            <tr>
                                <th>System</th>
                                <th>Status</th>
                                <th>Risk</th>
                                <th>Business Unit</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            {findings.slice(0, 5).map(finding => (
                                <tr key={finding.ci_id} className={`finding-row finding-${finding.status}`}>
                                    <td className="finding-system">{finding.ci_name}</td>
                                    <td>
                                        <StatusBadge status={finding.status} />
                                    </td>
                                    <td>
                                        <RiskScore score={finding.risk_score} />
                                    </td>
                                    <td className="finding-bu">{finding.business_unit}</td>
                                    <td className="finding-reason">{finding.reason}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

// Findings View Component
const FindingsView = ({ findings, onRefresh, loading }) => {
    const [filters, setFilters] = useState({
        business_unit: '',
        status: '',
        search: ''
    });

    // Filter findings based on current filters
    const filteredFindings = useMemo(() => {
        return findings.filter(finding => {
            if (filters.business_unit && finding.business_unit !== filters.business_unit) {
                return false;
            }
            if (filters.status && finding.status !== filters.status) {
                return false;
            }
            if (filters.search && !finding.ci_name.toLowerCase().includes(filters.search.toLowerCase())) {
                return false;
            }
            return true;
        });
    }, [findings, filters]);

    const businessUnits = useMemo(() => {
        return [...new Set(findings.map(f => f.business_unit))];
    }, [findings]);

    return (
        <div className="findings-view">
            <div className="findings-header">
                <h2>Compliance Findings</h2>
                <button 
                    onClick={() => onRefresh()} 
                    className="btn btn-secondary"
                    disabled={loading}
                >
                    {loading ? '🔄 Loading...' : '🔄 Refresh'}
                </button>
            </div>

            {/* Filters */}
            <div className="filters">
                <div className="filter-group">
                    <label>Business Unit:</label>
                    <select 
                        value={filters.business_unit} 
                        onChange={(e) => setFilters(prev => ({...prev, business_unit: e.target.value}))}
                    >
                        <option value="">All</option>
                        {businessUnits.map(bu => (
                            <option key={bu} value={bu}>{bu}</option>
                        ))}
                    </select>
                </div>

                <div className="filter-group">
                    <label>Status:</label>
                    <select 
                        value={filters.status} 
                        onChange={(e) => setFilters(prev => ({...prev, status: e.target.value}))}
                    >
                        <option value="">All</option>
                        <option value="pass">Pass</option>
                        <option value="warn">Warning</option>
                        <option value="fail">Fail</option>
                        <option value="unknown">Unknown</option>
                    </select>
                </div>

                <div className="filter-group">
                    <label>Search:</label>
                    <input 
                        type="text"
                        value={filters.search}
                        onChange={(e) => setFilters(prev => ({...prev, search: e.target.value}))}
                        placeholder="Search systems..."
                    />
                </div>
            </div>

            {/* Results count */}
            <div className="results-info">
                Showing {filteredFindings.length} of {findings.length} findings
            </div>

            {/* Findings Table */}
            <div className="findings-table-container">
                <table className="findings-table">
                    <thead>
                        <tr>
                            <th>System</th>
                            <th>Status</th>
                            <th>Risk Score</th>
                            <th>Business Unit</th>
                            <th>Reason</th>
                            <th>Evaluated</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredFindings.map(finding => (
                            <FindingRow key={finding.ci_id} finding={finding} />
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

// Finding Row Component
const FindingRow = ({ finding }) => {
    const [expanded, setExpanded] = useState(false);

    return (
        <>
            <tr className={`finding-row finding-${finding.status}`} onClick={() => setExpanded(!expanded)}>
                <td className="finding-system">
                    <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
                    {finding.ci_name}
                </td>
                <td><StatusBadge status={finding.status} /></td>
                <td><RiskScore score={finding.risk_score} /></td>
                <td className="finding-bu">{finding.business_unit}</td>
                <td className="finding-reason">{finding.reason}</td>
                <td className="finding-date">
                    {new Date(finding.evaluated_at).toLocaleString()}
                </td>
                <td>
                    <button className="btn btn-sm btn-secondary">Details</button>
                </td>
            </tr>
            {expanded && (
                <tr className="finding-details-row">
                    <td colSpan="7">
                        <div className="finding-details">
                            <div className="detail-section">
                                <h4>System Information</h4>
                                <p><strong>CI ID:</strong> {finding.ci_id}</p>
                                <p><strong>Business Unit:</strong> {finding.business_unit}</p>
                            </div>
                            {finding.remediation && (
                                <div className="detail-section">
                                    <h4>Recommended Remediation</h4>
                                    <p>{finding.remediation}</p>
                                </div>
                            )}
                        </div>
                    </td>
                </tr>
            )}
        </>
    );
};

// Policies View Component
const PoliciesView = ({ policies, onRefresh }) => {
    return (
        <div className="policies-view">
            <div className="policies-header">
                <h2>Compliance Policies</h2>
                <button onClick={onRefresh} className="btn btn-secondary">🔄 Refresh</button>
            </div>

            <div className="policies-grid">
                {policies.map(policy => (
                    <div key={policy.policy_id} className="policy-card">
                        <div className="policy-header">
                            <h3>{policy.name}</h3>
                            <div className={`policy-status ${policy.enabled ? 'enabled' : 'disabled'}`}>
                                {policy.enabled ? '✅ Enabled' : '❌ Disabled'}
                            </div>
                        </div>
                        <p className="policy-description">{policy.description}</p>
                        <div className="policy-meta">
                            <span>📋 {policy.rules_count} rules</span>
                            <span>📅 Updated {new Date(policy.last_modified).toLocaleDateString()}</span>
                        </div>
                        <div className="policy-actions">
                            <button className="btn btn-sm btn-primary">Edit</button>
                            <button className="btn btn-sm btn-secondary">Test</button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

// Scan View Component
const ScanView = ({ onStartScan, scanProgress, loading }) => {
    const [scanConfig, setScanConfig] = useState({
        target_ips: ['10.1.1.10', '10.1.2.20', '10.1.3.30', '10.1.0.1'],
        business_unit: '',
        scan_types: ['ssh', 'winrm', 'snmp'],
        priority: 'normal'
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        onStartScan(scanConfig);
    };

    return (
        <div className="scan-view">
            <h2>Start Compliance Scan</h2>
            
            <form onSubmit={handleSubmit} className="scan-form">
                <div className="form-group">
                    <label>Target IP Addresses</label>
                    <textarea
                        value={scanConfig.target_ips.join('\n')}
                        onChange={(e) => setScanConfig(prev => ({
                            ...prev,
                            target_ips: e.target.value.split('\n').filter(ip => ip.trim())
                        }))}
                        placeholder="Enter IP addresses, one per line"
                        rows="6"
                    />
                </div>
                
                <div className="form-group">
                    <label>Business Unit (optional)</label>
                    <select
                        value={scanConfig.business_unit}
                        onChange={(e) => setScanConfig(prev => ({
                            ...prev,
                            business_unit: e.target.value
                        }))}
                    >
                        <option value="">All Business Units</option>
                        <option value="Finance">Finance</option>
                        <option value="Marketing">Marketing</option>
                        <option value="Engineering">Engineering</option>
                        <option value="IT Operations">IT Operations</option>
                    </select>
                </div>
                
                <div className="form-group">
                    <label>Scan Types</label>
                    <div className="checkbox-group">
                        {['ssh', 'winrm', 'snmp', 'napalm', 'nmap'].map(type => (
                            <label key={type} className="checkbox-label">
                                <input
                                    type="checkbox"
                                    checked={scanConfig.scan_types.includes(type)}
                                    onChange={(e) => {
                                        const types = e.target.checked
                                            ? [...scanConfig.scan_types, type]
                                            : scanConfig.scan_types.filter(t => t !== type);
                                        setScanConfig(prev => ({...prev, scan_types: types}));
                                    }}
                                />
                                {type.toUpperCase()}
                            </label>
                        ))}
                    </div>
                </div>
                
                <div className="form-group">
                    <label>Priority</label>
                    <select
                        value={scanConfig.priority}
                        onChange={(e) => setScanConfig(prev => ({
                            ...prev,
                            priority: e.target.value
                        }))}
                    >
                        <option value="low">Low</option>
                        <option value="normal">Normal</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                </div>
                
                <button 
                    type="submit" 
                    className="btn btn-primary btn-large"
                    disabled={loading || scanConfig.target_ips.length === 0}
                >
                    {loading ? '🔄 Starting...' : '🚀 Start Scan'}
                </button>
            </form>
            
            {scanProgress && (
                <div className="scan-progress-section">
                    <h3>Current Scan Progress</h3>
                    <div className="progress-details">
                        <p>Scan ID: {scanProgress.scan_id}</p>
                        <p>Status: {scanProgress.status}</p>
                        <p>Progress: {scanProgress.completed}/{scanProgress.total} systems</p>
                        <div className="progress-bar">
                            <div 
                                className="progress-fill" 
                                style={{ width: `${scanProgress.progress || 0}%` }}
                            ></div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

// Utility Components
const StatusBadge = ({ status }) => {
    const config = {
        pass: { icon: '✅', label: 'Pass', className: 'status-pass' },
        warn: { icon: '⚠️', label: 'Warning', className: 'status-warn' },
        fail: { icon: '❌', label: 'Fail', className: 'status-fail' },
        unknown: { icon: '❓', label: 'Unknown', className: 'status-unknown' }
    };
    
    const statusConfig = config[status] || config.unknown;
    
    return (
        <span className={`status-badge ${statusConfig.className}`}>
            <span className="status-icon">{statusConfig.icon}</span>
            <span className="status-label">{statusConfig.label}</span>
        </span>
    );
};

const RiskScore = ({ score }) => {
    const getRiskLevel = (score) => {
        if (score >= 80) return { level: 'critical', color: '#f44336' };
        if (score >= 60) return { level: 'high', color: '#ff9800' };
        if (score >= 30) return { level: 'medium', color: '#ffeb3b' };
        if (score > 0) return { level: 'low', color: '#8bc34a' };
        return { level: 'none', color: '#4caf50' };
    };
    
    const risk = getRiskLevel(score);
    
    return (
        <span 
            className={`risk-score risk-${risk.level}`}
            style={{ backgroundColor: risk.color }}
        >
            {score}
        </span>
    );
};

// Footer Component
const Footer = () => {
    return (
        <footer className="footer">
            <div className="footer-content">
                <div className="footer-section">
                    <span>🏢 Enterprise CMDB Compliance Tool</span>
                    <span>Built with FastAPI, React, and OpenTelemetry</span>
                </div>
                <div className="footer-section">
                    <span>Version 1.0.0</span>
                    <span>© 2024 Enterprise Security Team</span>
                </div>
            </div>
        </footer>
    );
};

// Initialize React App
const container = document.getElementById('react-app');
if (container) {
    const root = ReactDOM.createRoot(container);
    root.render(<App />);
}