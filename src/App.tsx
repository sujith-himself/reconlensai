import React, { useState } from 'react';
import { Search, Loader2, Shield, Activity, Lock, Globe, Database, Server } from 'lucide-react';

export default function App() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const analyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const isRawHttp = target.startsWith('GET') || target.startsWith('POST') || target.startsWith('HTTP/');
      const payload = isRawHttp ? { rawHttp: target } : { url: target };
      
      const res = await fetch('http://localhost:3001/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) throw new Error('Analysis failed');
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cyber-container">
      <header className="cyber-header">
        <Shield className="logo-icon" />
        <h1>ReconLens AI</h1>
        <p>AI-Powered HTTP Security Intelligence</p>
      </header>

      <main className="cyber-main">
        <form onSubmit={analyze} className="cyber-form">
          <div className="input-group">
            <Search className="input-icon" />
            <input 
              type="text" 
              placeholder="Enter target URL or paste raw HTTP request..."
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="cyber-input"
              disabled={loading}
            />
          </div>
          <button type="submit" className="cyber-button" disabled={loading || !target}>
            {loading ? (
              <><Loader2 className="spin-icon" /> ANALYZING...</>
            ) : (
              'INITIATE SCAN'
            )}
          </button>
        </form>

        {error && (
          <div className="cyber-alert error">
            <Activity /> {error}
          </div>
        )}

        {result && (
          <div className="cyber-report">
            <div className="report-header">
              <h2>Target: {result.target}</h2>
              <div className="report-badges">
                <span className={`badge ${result.risk.toLowerCase()}`}>
                  Risk: {result.risk} ({result.score}/100)
                </span>
                <span className="badge neutral">Endpoint: {result.endpoint}</span>
                <span className="badge neutral">Duration: {result.duration}</span>
              </div>
            </div>

            {/* AI Summary */}
            <section className="report-section highlight">
              <h3>Executive Summary (AI)</h3>
              <p>{result.summary}</p>
            </section>

            {/* Recommendations */}
            <section className="report-section highlight-border">
              <h3>Prioritized Recommendations</h3>
              <ul className="cyber-list">
                {result.recommendations.map((r: any, i: number) => (
                  <li key={i}>
                    <strong>{r.title}</strong>: {r.detail}
                  </li>
                ))}
              </ul>
            </section>

            {/* Grid Layout for details */}
            <div className="report-grid">
              
              <div className="report-card">
                <h3><Server className="icon-sm" /> Technologies</h3>
                <ul className="cyber-list dense">
                  {result.technologies.map((t: any, i: number) => (
                    <li key={i}>
                      <span className="tech-name">{t.name}</span>
                      <span className="tech-cat">{t.category}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="report-card">
                <h3><Lock className="icon-sm" /> Security Headers</h3>
                <ul className="cyber-list dense">
                  {result.securityHeaders.map((h: any, i: number) => (
                    <li key={i} className={`status-${h.status}`}>
                      <strong>{h.header}</strong>: {h.description}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="report-card">
                <h3><Database className="icon-sm" /> Sensitive Paths</h3>
                <ul className="cyber-list dense">
                  {result.sensitivePaths.filter((p: any) => p.status === 'found').map((p: any, i: number) => (
                    <li key={i} className="status-error">
                      <strong>{p.path}</strong> - {p.label}
                    </li>
                  ))}
                  {result.sensitivePaths.filter((p: any) => p.status === 'found').length === 0 && (
                    <li className="status-ok">No exposed sensitive paths found.</li>
                  )}
                </ul>
              </div>

              <div className="report-card">
                <h3><Globe className="icon-sm" /> OSINT & Recon</h3>
                <div className="osint-stats">
                  <div><strong>Subdomains found:</strong> {result.osint?.subdomains?.length || 0}</div>
                  <div><strong>Shared Hosting:</strong> {result.osint?.sharedHosting ? 'Yes' : 'No'}</div>
                  <div><strong>Email Spoofing Risk:</strong> {result.osint?.dns?.emailSpoofingRisk || 'Unknown'}</div>
                </div>
              </div>
            </div>

          </div>
        )}
      </main>
    </div>
  );
}
