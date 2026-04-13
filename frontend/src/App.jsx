import { useEffect, useMemo, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'

const tabs = [
  { key: 'overview', label: 'Overview & Map' },
  { key: 'infrastructure', label: 'Infrastructure' },
  { key: 'threat', label: 'Threat Intel' },
  { key: 'web', label: 'Web Analysis' }
]

function GeoMap({ lat, lon, domain, ip }) {
  if (lat === undefined || lat === null || lon === undefined || lon === null) {
    return <p className="empty">No geolocation coordinates available for this IP.</p>
  }

  const delta = 0.15
  const left = Math.max(-180, lon - delta)
  const right = Math.min(180, lon + delta)
  const bottom = Math.max(-90, lat - delta)
  const top = Math.min(90, lat + delta)
  const bbox = `${left},${bottom},${right},${top}`
  const marker = `${lat},${lon}`
  const src = `https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent(bbox)}&layer=mapnik&marker=${encodeURIComponent(marker)}`

  return (
    <div className="map-card">
      <iframe
        title="IP geolocation map"
        src={src}
        className="geo-map"
        loading="lazy"
      />
      <p className="map-caption">
        Live location for {domain} ({ip || 'Unknown IP'}) at [{lat}, {lon}]
      </p>
    </div>
  )
}

function JsonBlock({ data }) {
  return <pre className="json-block">{JSON.stringify(data, null, 2)}</pre>
}

function Metric({ label, value, status }) {
  return (
    <div className="metric-card">
      <p className="metric-label">{label}</p>
      <p className={`metric-value ${status || ''}`}>{value ?? 'N/A'}</p>
    </div>
  )
}

function SafeTable({ rows }) {
  if (!rows || rows.length === 0) {
    return <p className="empty">No data available.</p>
  }

  const headers = Object.keys(rows[0])
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={idx}>
              {headers.map((h) => (
                <td key={h}>{String(row[h] ?? '')}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')
  const [domain, setDomain] = useState('google.com')
  const [activeScan, setActiveScan] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [tab, setTab] = useState('overview')

  const riskClass = useMemo(() => {
    const score = result?.['Risk Score'] ?? 0
    if (score >= 50) return 'bad'
    if (score >= 20) return 'warn'
    return 'good'
  }, [result])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  async function runAnalysis(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, active_scan: activeScan })
      })
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}))
        throw new Error(detail.detail || `Request failed with ${res.status}`)
      }
      const data = await res.json()
      setResult(data)
    } catch (err) {
      setError(err.message || 'Unknown error')
      setResult(null)
    } finally {
      setLoading(false)
    }
  }

  const threat = result?.['Threat Intel'] || {}
  const web = result?.['Web Analysis'] || {}
  const hosted = result?.['Hosted Discovery'] || {}
  const dns = result?.DNS || {}
  const whois = result?.WHOIS || {}
  const ssl = result?.SSL || {}
  const crt = result?.['Certificate Transparency'] || {}
  const passiveSources = result?.['Passive Sources'] || {}
  const shodanPassive = passiveSources.Shodan || {}
  const censysPassive = passiveSources.Censys || {}
  const activePortScan = result?.['Active Port Scan'] || null
  const riskBreakdown = result?.['Risk Breakdown'] || {}
  const riskComposite = riskBreakdown.composite || {}
  const riskComponents = riskBreakdown.components || {}
  const riskWeights = riskBreakdown.weights || {}
  const suspiciousKeywords = web.content_keywords || []
  const missingHeaders = web.missing || []
  const rblHits = result?.['RBL Hits'] || []

  const breakdownLabels = {
    malware_intel: 'Malware Intel',
    abuse_reputation: 'Abuse Reputation',
    infrastructure_risk: 'Infrastructure Risk',
    domain_trust_risk: 'Domain Trust Risk'
  }

  const signalCards = [
    {
      label: 'Suspicious Keywords',
      value: suspiciousKeywords.length,
      tone: suspiciousKeywords.length > 0 ? 'bad' : 'good'
    },
    {
      label: 'Missing Security Headers',
      value: missingHeaders.length,
      tone: missingHeaders.length > 0 ? 'warn' : 'good'
    },
    {
      label: 'RBL Blacklist Hits',
      value: rblHits.length,
      tone: rblHits.length > 0 ? 'bad' : 'good'
    },
    {
      label: 'VirusTotal Detections',
      value: threat.VirusTotal?.malicious ?? 0,
      tone: (threat.VirusTotal?.malicious ?? 0) > 0 ? 'bad' : 'good'
    },
    {
      label: 'URLHaus Malware URLs',
      value: threat.URLHaus?.malware_urls ?? 0,
      tone: (threat.URLHaus?.malware_urls ?? 0) > 0 ? 'bad' : 'good'
    },
    {
      label: 'IPQS Fraud Score',
      value: threat.IPQualityScore?.fraud_score ?? 0,
      tone: (threat.IPQualityScore?.fraud_score ?? 0) >= 75 ? 'bad' : 'warn'
    },
    {
      label: 'AbuseIPDB Score',
      value: `${threat.AbuseIPDB?.score ?? 0}%`,
      tone: (threat.AbuseIPDB?.score ?? 0) > 25 ? 'warn' : 'good'
    },
    {
      label: 'SSL Status',
      value: ssl.status || 'Unknown',
      tone: ssl.status === 'VALID' ? 'good' : 'warn'
    },
    {
      label: 'SPF / DMARC',
      value: `${dns.spf || 'MISSING'} / ${dns.dmarc || 'MISSING'}`,
      tone: dns.spf === 'PRESENT' && dns.dmarc === 'PRESENT' ? 'good' : 'warn'
    },
    {
      label: 'Domain Age (days)',
      value: whois.age_days ?? 'N/A',
      tone: whois.age_days !== null && whois.age_days < 30 ? 'warn' : 'good'
    }
  ]

  return (
    <div className="page">
      <header className="header">
        <div className="header-bar">
          <h1>Domain Intel 360°</h1>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          >
            {theme === 'dark' ? 'Switch to Bright Theme' : 'Switch to Dark Theme'}
          </button>
        </div>
        <p>Enterprise-grade domain reputation and infrastructure analysis.</p>
      </header>

      <form className="controls" onSubmit={runAnalysis}>
        <div className="field">
          <label htmlFor="domain">Target Domain</label>
          <input
            id="domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            required
          />
        </div>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={activeScan}
            onChange={(e) => setActiveScan(e.target.checked)}
          />
          Run Active Port Scan
        </label>
        <button type="submit" disabled={loading}>
          {loading ? 'Running...' : 'Run Analysis'}
        </button>
      </form>

      {error && <div className="alert error">{error}</div>}

      {result && (
        <>
          <section className="metrics-grid">
            <Metric label="Risk Score" value={`${result['Risk Score']}/100`} status={riskClass} />
            <Metric label="Verdict" value={result.Verdict} status={riskClass} />
            <Metric label="Primary IP" value={result.IP} />
            <Metric label="Subdomains Found" value={crt.count ?? 0} />
          </section>

          <section className="factors">
            <h3>Risk Factors</h3>
            {result['Risk Factors']?.length ? (
              <ul>
                {result['Risk Factors'].map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            ) : (
              <p className="empty">No risk factors found.</p>
            )}

            <h3>Risk Model Breakdown</h3>
            <div className="breakdown-summary">
              <div className="risk-card">
                <p className="risk-label">Composite Score</p>
                <p className={`risk-value ${riskClass}`}>{riskComposite.score ?? result['Risk Score']}</p>
              </div>
              <div className="risk-card">
                <p className="risk-label">Model Verdict</p>
                <p className={`risk-value ${riskClass}`}>{riskComposite.verdict || result.Verdict}</p>
              </div>
              <div className="risk-card">
                <p className="risk-label">Confidence</p>
                <p className="risk-value good">{riskComposite.confidence ?? 'N/A'}{riskComposite.confidence !== undefined ? '%' : ''}</p>
              </div>
            </div>

            <div className="component-grid">
              {Object.entries(riskComponents).map(([key, value]) => (
                <div key={key} className="component-card">
                  <div className="component-header">
                    <p className="risk-label">{breakdownLabels[key] || key}</p>
                    <p className="risk-value warn">{Number(value).toFixed(2)}</p>
                  </div>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${Math.max(0, Math.min(100, Number(value)))}%` }} />
                  </div>
                  <p className="weight-label">Weight: {riskWeights[key] ?? 0}</p>
                </div>
              ))}
            </div>

            <h3>Risk Intelligence Details</h3>
            <div className="risk-grid">
              {signalCards.map((signal) => (
                <div key={signal.label} className="risk-card">
                  <p className="risk-label">{signal.label}</p>
                  <p className={`risk-value ${signal.tone}`}>{String(signal.value)}</p>
                </div>
              ))}
            </div>

            <div className="risk-evidence-grid">
              <div className="evidence-block">
                <p className="risk-label">Suspicious Keywords</p>
                {suspiciousKeywords.length > 0 ? (
                  <div className="chip-wrap">
                    {suspiciousKeywords.map((k) => (
                      <span key={k} className="chip bad">{k}</span>
                    ))}
                  </div>
                ) : (
                  <p className="empty">No suspicious keywords found.</p>
                )}
              </div>

              <div className="evidence-block">
                <p className="risk-label">Missing Security Headers</p>
                {missingHeaders.length > 0 ? (
                  <div className="chip-wrap">
                    {missingHeaders.map((h) => (
                      <span key={h} className="chip warn">{h}</span>
                    ))}
                  </div>
                ) : (
                  <p className="empty">No critical headers missing.</p>
                )}
              </div>

              <div className="evidence-block">
                <p className="risk-label">RBL Providers Listing This IP</p>
                {rblHits.length > 0 ? (
                  <div className="chip-wrap">
                    {rblHits.map((rbl) => (
                      <span key={rbl} className="chip bad">{rbl}</span>
                    ))}
                  </div>
                ) : (
                  <p className="empty">No RBL listings detected.</p>
                )}
              </div>
            </div>
          </section>

          <nav className="tabs">
            {tabs.map((t) => (
              <button
                key={t.key}
                className={tab === t.key ? 'active' : ''}
                onClick={() => setTab(t.key)}
                type="button"
              >
                {t.label}
              </button>
            ))}
          </nav>

          {tab === 'overview' && (
            <section className="panel two-col">
              <div>
                <h3>Identity</h3>
                <p><strong>Registrar:</strong> {whois.registrar || 'Unknown'}</p>
                <p><strong>Domain Age:</strong> {whois.age_days ?? 'N/A'} days</p>
                <p><strong>ISP:</strong> {result.Geo?.isp || 'Unknown'}</p>
                <p><strong>Reverse DNS:</strong> {result['Reverse DNS'] || 'N/A'}</p>
                <p><strong>Geo:</strong> {result.Geo?.country || 'Unknown'}, {result.Geo?.city || 'Unknown'}</p>
              </div>
              <div>
                <h3>DNS & SSL</h3>
                <p><strong>SPF:</strong> {dns.spf}</p>
                <p><strong>DMARC:</strong> {dns.dmarc}</p>
                <p><strong>SSL Status:</strong> {ssl.status}</p>
                <p><strong>SSL Issuer:</strong> {ssl.issuer}</p>
                <p><strong>SSL Days Left:</strong> {ssl.days_left}</p>
              </div>

              <div className="full-width">
                <h3>Live Geo Mapping</h3>
                <GeoMap
                  lat={result.Geo?.lat}
                  lon={result.Geo?.lon}
                  domain={result.Domain}
                  ip={result.IP}
                />
              </div>
            </section>
          )}

          {tab === 'infrastructure' && (
            <section className="panel">
              <h3>Passive Ports (Merged)</h3>
              <SafeTable rows={(result['Passive Ports'] || []).map((p) => ({ Port: p, Service: 'Passive Intel' }))} />

              <h3>Passive Source: Shodan InternetDB</h3>
              <p><strong>Status:</strong> {shodanPassive.status || 'Success'}</p>
              <SafeTable rows={(shodanPassive.ports || []).map((p) => ({ Port: p, Source: 'Shodan' }))} />

              <h3>Passive Source: Censys</h3>
              <p><strong>Status:</strong> {censysPassive.status || 'No Data'}</p>
              <SafeTable rows={(censysPassive.ports || []).map((p) => ({ Port: p, Source: 'Censys' }))} />

              <h3>Active Port Scan</h3>
              <p><strong>Engine:</strong> {activePortScan?.engine || 'unavailable'}</p>
              <p><strong>Status:</strong> {activePortScan?.status || 'No scan data available'}</p>
              {activePortScan?.engine === 'disabled' && (
                <p className="empty">Enable "Run Active Port Scan" and run analysis again.</p>
              )}
              {activePortScan?.fallback_reason && (
                <p><strong>Fallback:</strong> {activePortScan.fallback_reason}</p>
              )}
              <SafeTable rows={activePortScan?.ports || []} />

              <h3>Certificate Transparency</h3>
              <SafeTable rows={crt.certificates || []} />

              <h3>Host Records (AlienVault)</h3>
              <SafeTable rows={threat['AlienVault Host Records']?.records || []} />
            </section>
          )}

          {tab === 'threat' && (
            <section className="panel two-col">
              <div>
                <h3>Threat Metrics</h3>
                <Metric label="VirusTotal Detections" value={threat.VirusTotal?.malicious ?? 0} />
                <Metric label="AlienVault Pulses" value={threat.AlienVault?.pulses ?? 0} />
                <Metric label="AbuseIPDB Score" value={`${threat.AbuseIPDB?.score ?? 0}%`} />
                <Metric label="IPQS Fraud Score" value={threat.IPQualityScore?.fraud_score ?? 0} />
              </div>
              <div>
                <h3>Provider Results</h3>
                <JsonBlock data={{
                  URLHaus: threat.URLHaus,
                  Pulsedive: threat.Pulsedive,
                  GreyNoise: threat.GreyNoise,
                  VPNAPI: threat.VPNAPI,
                  BlocklistDE: threat['Blocklist.de']
                }} />
              </div>
            </section>
          )}

          {tab === 'web' && (
            <section className="panel two-col">
              <div>
                <h3>URLScan</h3>
                <p><strong>Status:</strong> {threat.URLScan?.status || 'Unknown'}</p>
                <p><strong>Total:</strong> {threat.URLScan?.total ?? 0}</p>
                <p><strong>Malicious:</strong> {String(threat.URLScan?.malicious ?? false)}</p>
                <p><strong>Country:</strong> {threat.URLScan?.country || 'Unknown'}</p>
                {threat.URLScan?.screenshot && (
                  <a href={threat.URLScan.screenshot} target="_blank" rel="noreferrer">
                    Open latest screenshot
                  </a>
                )}
              </div>
              <div>
                <h3>Headers & Content</h3>
                <p><strong>Grade:</strong> {web.grade || 'F'}</p>
                <p><strong>Server:</strong> {web.server || 'Unknown'}</p>
                <p><strong>Missing Headers:</strong> {(web.missing || []).join(', ') || 'None'}</p>
                <p><strong>Suspicious Keywords:</strong> {(web.content_keywords || []).join(', ') || 'None'}</p>
                <JsonBlock data={web.headers || {}} />
              </div>

              <div>
                <h3>Hosted Websites Discovery</h3>
                <p><strong>Status:</strong> {hosted.status || 'No Data'}</p>
                <p><strong>Hosted Sites:</strong> {hosted.counts?.hosted_sites ?? 0}</p>
                <p><strong>Reachable Sites:</strong> {hosted.counts?.reachable_sites ?? 0}</p>
                <SafeTable rows={(hosted.hosted_sites || []).map((site) => ({ Site: site }))} />
              </div>

              <div>
                <h3>Discovered Webpages</h3>
                <p><strong>Webpages Found:</strong> {hosted.counts?.webpages ?? 0}</p>
                <SafeTable rows={(hosted.webpages || []).map((page) => ({ URL: page }))} />
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}
