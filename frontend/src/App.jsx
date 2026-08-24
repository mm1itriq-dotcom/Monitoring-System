import { useState, useEffect, useRef, useCallback } from 'react';
import Chart from 'chart.js/auto';

function App() {
    const [logs, setLogs] = useState([]);
    const [threats, setThreats] = useState([]);
    const [stats, setStats] = useState({
        totalLogs: 0,
        activeThreats: 0,
        maxScore: 0,
        firewallBlocks: 0
    });
    const [activeTab, setActiveTab] = useState('feed');
    const [ipLookup, setIpLookup] = useState('');
    const [ipResult, setIpResult] = useState(null);
    const [blacklist, setBlacklist] = useState({ ip: '', reason: '' });
    const [blacklistStatus, setBlacklistStatus] = useState('');

    const wsRef = useRef(null);

    // WebSocket Connection Initialization
    useEffect(() => {
        const connectWebSocket = () => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            // Use window.location.host so it works when served by the backend, 
            // or fallback to localhost:8000 if running in dev mode
            const host = window.location.port === '5173' ? 'localhost:8000' : window.location.host;
            const wsUrl = `${protocol}//${host}/ws/logs`;
            const ws = new WebSocket(wsUrl);
            wsRef.current = ws;

            ws.onopen = () => console.log('WebSocket Connected');
            ws.onclose = () => {
                console.log('WebSocket Disconnected, reconnecting...');
                setTimeout(connectWebSocket, 3000);
            };

            ws.onmessage = (event) => {
                try {
                    const payload = JSON.parse(event.data);
                    if (payload.event === 'new_log') {
                        handleNewLog(payload.data);
                    } else if (payload.event === 'threat_alert') {
                        handleNewThreat(payload.data);
                    }
                } catch (e) {
                    console.error('Failed to parse WS payload', e);
                }
            };
        };

        connectWebSocket();
        fetchInitialData();

        return () => {
            if (wsRef.current) wsRef.current.close();
        };
    }, []);

    const fetchInitialData = async () => {
        const baseUrl = window.location.port === '5173' ? 'http://localhost:8000' : '';
        try {
            const [threatsRes, statsRes, logsRes] = await Promise.all([
                fetch(`${baseUrl}/api/threats`),
                fetch(`${baseUrl}/api/threats/stats`),
                fetch(`${baseUrl}/api/logs/recent`)
            ]);
            const threatsData = await threatsRes.json();
            const statsData = await statsRes.json();
            const logsData = await logsRes.json();

            setThreats(threatsData);
            setLogs(logsData);
            setStats(prev => ({
                ...prev,
                totalLogs: logsData.length,
                activeThreats: statsData.unresolved_threats || 0
            }));
        } catch (err) {
            console.error('Error loading initial API data', err);
        }
    };

    const handleNewLog = (log) => {
        setLogs(prev => [log, ...prev.slice(0, 199)]);
        setStats(prev => ({
            ...prev,
            totalLogs: prev.totalLogs + 1,
            firewallBlocks: log.event_type === 'firewall_block' ? prev.firewallBlocks + 1 : prev.firewallBlocks
        }));
    };

    const handleNewThreat = (threat) => {
        setThreats(prev => [threat, ...prev]);
        setStats(prev => ({
            ...prev,
            activeThreats: prev.activeThreats + 1,
            maxScore: Math.max(prev.maxScore, threat.threat_score || 0)
        }));
    };

    const resolveThreat = async (id) => {
        const baseUrl = window.location.port === '5173' ? 'http://localhost:8000' : '';
        try {
            await fetch(`${baseUrl}/api/threats/${id}/resolve`, { method: 'POST' });
            setThreats(prev => prev.map(t => t.id === id ? { ...t, is_resolved: true } : t));
            setStats(prev => ({ ...prev, activeThreats: Math.max(0, prev.activeThreats - 1) }));
        } catch (e) {
            console.error('Failed to resolve threat', e);
        }
    };

    const queryIP = async () => {
        if (!ipLookup.trim()) return;
        const baseUrl = window.location.port === '5173' ? 'http://localhost:8000' : '';
        try {
            const res = await fetch(`${baseUrl}/api/ip/${ipLookup.trim()}/info`);
            const data = await res.json();
            setIpResult(data);
        } catch (e) {
            console.error('IP query failed', e);
        }
    };

    const submitBlacklist = async () => {
        if (!blacklist.ip.trim()) return;
        const baseUrl = window.location.port === '5173' ? 'http://localhost:8000' : '';
        try {
            const res = await fetch(`${baseUrl}/api/ip/blacklist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: blacklist.ip.trim(), reason: blacklist.reason })
            });
            const data = await res.json();
            setBlacklistStatus(data.message || 'IP Blacklisted successfully!');
            setBlacklist({ ip: '', reason: '' });
        } catch (e) {
            setBlacklistStatus('Failed to blacklist IP.');
        }
    };

    return (
        <div style={{ maxWidth: '87.5rem', margin: '0 auto' }}>
            {/* Header */}
            <div className="header glass-panel">
                <div className="header-title">
                    <div className="pulse-dot"></div>
                    <h1>Threat Intelligence & Monitoring System</h1>
                    <span style={{ fontSize: '0.6875rem', background: 'rgba(6,182,212,0.15)', color: 'var(--accent-cyan)', padding: '0.1875rem 0.5rem', borderRadius: '0.375rem', fontWeight: 700 }}>VITE + REACT v18</span>
                </div>
            </div>

            {/* Metrics Grid */}
            <div className="metrics-grid">
                <div className="metric-card glass-panel">
                    <div className="card-title">Total Ingested Logs</div>
                    <div className="card-value">{stats.totalLogs}</div>
                    <div className="card-sub">⚡ Real-time WebSocket Stream</div>
                </div>
                <div className="metric-card glass-panel">
                    <div className="card-title">Unresolved Threat Alerts</div>
                    <div className="card-value" style={{ color: 'var(--severity-crit)' }}>{stats.activeThreats}</div>
                    <div className="card-sub">🚨 Action required</div>
                </div>
                <div className="metric-card glass-panel">
                    <div className="card-title">Peak Threat Severity</div>
                    <div className="card-value" style={{ color: 'var(--severity-high)' }}>{stats.maxScore}/100</div>
                    <div className="card-sub">🔥 Statistical & Rule Engine</div>
                </div>
                <div className="metric-card glass-panel">
                    <div className="card-title">Firewall Block Events</div>
                    <div className="card-value" style={{ color: 'var(--severity-med)' }}>{stats.firewallBlocks}</div>
                    <div className="card-sub">🛡️ pfSense Firewall</div>
                </div>
            </div>

            {/* Navigation Tabs */}
            <div className="tabs">
                <button className={`tab-btn ${activeTab === 'feed' ? 'active' : ''}`} onClick={() => setActiveTab('feed')}>
                    📡 Live Log Feed
                </button>
                <button className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}>
                    🚨 Threat Alerts ({threats.filter(t => !t.is_resolved).length})
                </button>
                <button className={`tab-btn ${activeTab === 'analytics' ? 'active' : ''}`} onClick={() => setActiveTab('analytics')}>
                    📊 Analytics & Timeline
                </button>
                <button className={`tab-btn ${activeTab === 'ip' ? 'active' : ''}`} onClick={() => setActiveTab('ip')}>
                    🔎 IP Intelligence
                </button>
            </div>

            {/* Tab 1: Live Feed */}
            {activeTab === 'feed' && (
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem', alignItems: 'center' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Real-Time Log Stream</h3>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Showing last 200 logs</span>
                    </div>
                    <div className="feed-container">
                        {logs.length === 0 ? (
                            <div style={{ textAlign: 'center', color: 'var(--text-muted)', paddingTop: '9.375rem' }}>
                                Waiting for incoming log stream...
                            </div>
                        ) : (
                            logs.map((l, i) => (
                                <div key={l.id || i} className="feed-row">
                                    <div>
                                        <span style={{ color: '#64748b', marginRight: '0.625rem' }}>
                                            [{l.timestamp ? (l.timestamp.includes('T') ? l.timestamp.split('T')[1].slice(0, 8) : l.timestamp) : '00:00:00'}]
                                        </span>
                                        <strong style={{ color: 'var(--accent-cyan)' }}>{l.source_ip || '127.0.0.1'}</strong>
                                        <span style={{ margin: '0 0.5rem', color: 'var(--text-muted)' }}>→</span>
                                        <span>{l.destination_ip || '10.0.0.1'}</span>
                                        <span style={{ marginLeft: '0.75rem', color: '#cbd5e1' }}>{l.event_type}</span>
                                    </div>
                                    <div>
                                        <span className={`badge-sev ${l.severity || 'Low'}`}>{l.severity || 'Low'}</span>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}

            {/* Tab 2: Threat Alerts */}
            {activeTab === 'threats' && (
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.25rem', alignItems: 'center' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Security Threat Alerts</h3>
                        <button className="btn" onClick={fetchInitialData}>Refresh Threat List</button>
                    </div>
                    <div className="threat-grid">
                        {threats.length === 0 ? (
                            <div style={{ color: 'var(--text-muted)' }}>No security threat alerts recorded.</div>
                        ) : (
                            threats.map(t => (
                                <div key={t.id} className={`threat-card ${t.severity}`}>
                                    <div className="threat-header">
                                        <div>
                                            <strong style={{ fontSize: '0.9375rem', color: '#fff' }}>{t.threat_type}</strong>
                                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                                                Source: <span style={{ color: 'var(--accent-cyan)' }}>{t.source_ip}</span>
                                            </div>
                                        </div>
                                        <div className="threat-score">{t.threat_score}/100</div>
                                    </div>
                                    <div className="threat-desc">{t.description}</div>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                        <span className={`badge-sev ${t.severity}`}>{t.severity}</span>
                                        {t.is_resolved ? (
                                            <span style={{ color: 'var(--severity-low)', fontSize: '0.75rem', fontWeight: 700 }}>
                                                ✓ RESOLVED
                                            </span>
                                        ) : (
                                            <button className="btn" style={{ padding: '0.3125rem 0.75rem', fontSize: '0.75rem' }} onClick={() => resolveThreat(t.id)}>
                                                Resolve Alert
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}

            {/* Tab 3: Analytics */}
            {activeTab === 'analytics' && <AnalyticsComponent />}

            {/* Tab 4: IP Intelligence */}
            {activeTab === 'ip' && (
                <div className="grid-2">
                    <div className="glass-panel" style={{ padding: '1.5rem' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem' }}>IP Threat Lookup</h3>
                        <div className="form-group">
                            <label className="form-label">IP Address</label>
                            <input type="text" className="form-input" placeholder="e.g. 192.168.1.50" value={ipLookup} onChange={e => setIpLookup(e.target.value)} />
                        </div>
                        <button className="btn" onClick={queryIP}>Query IP Intelligence</button>
                        {ipResult && (
                            <div style={{ marginTop: '1.25rem', background: 'rgba(7,10,18,0.7)', padding: '1rem', borderRadius: '0.5rem', border: '0.0625rem solid rgba(255,255,255,0.08)' }}>
                                <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '0.625rem' }}>{ipResult.ip_address}</h4>
                                <p style={{ fontSize: '0.8125rem', marginBottom: '0.375rem' }}>Total Ingested Logs: <strong>{ipResult.total_logs}</strong></p>
                                <p style={{ fontSize: '0.8125rem', marginBottom: '0.375rem' }}>Threat Count: <strong>{ipResult.threat_count}</strong></p>
                                <p style={{ fontSize: '0.8125rem', marginBottom: '0.375rem' }}>Peak Threat Score: <strong style={{ color: 'var(--severity-crit)' }}>{ipResult.max_threat_score}/100</strong></p>
                                <p style={{ fontSize: '0.8125rem' }}>Blacklist Status: <strong>{ipResult.is_blacklisted ? '🔴 BLACKLISTED' : '🟢 CLEAR'}</strong></p>
                            </div>
                        )}
                    </div>

                    <div className="glass-panel" style={{ padding: '1.5rem' }}>
                        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem' }}>Blacklist IP Address</h3>
                        <div className="form-group">
                            <label className="form-label">Target IP Address</label>
                            <input type="text" className="form-input" placeholder="e.g. 185.220.101.4" value={blacklist.ip} onChange={e => setBlacklist({ ...blacklist, ip: e.target.value })} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Violation Reason</label>
                            <input type="text" className="form-input" placeholder="Repeated SSH brute force attempts" value={blacklist.reason} onChange={e => setBlacklist({ ...blacklist, reason: e.target.value })} />
                        </div>
                        <button className="btn" style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)' }} onClick={submitBlacklist}>
                            Add to Blacklist
                        </button>
                        {blacklistStatus && (
                            <div style={{ marginTop: '0.875rem', fontSize: '0.8125rem', color: 'var(--accent-cyan)' }}>{blacklistStatus}</div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

// Sub-component for Chart.js Analytics
function AnalyticsComponent() {
    const chartRef = useRef(null);

    useEffect(() => {
        const ctx = chartRef.current.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['13:00', '13:05', '13:10', '13:15', '13:20', '13:25', '13:30', '13:35'],
                datasets: [{
                    label: 'Log Traffic Volume (Req/Min)',
                    data: [18, 25, 32, 28, 45, 60, 52, 75],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.15)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#f8fafc', font: { family: 'Plus Jakarta Sans', weight: '600' } } }
                },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });

        return () => chart.destroy();
    }, []);

    return (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1.25rem' }}>Statistical Traffic & Anomaly Analysis</h3>
            <canvas ref={chartRef} height="100"></canvas>
        </div>
    );
}

export default App;
