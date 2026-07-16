// Small shared UI atoms

export function SeverityBadge({ severity }) {
  return <span className={`sev-badge sev-${severity}`}>{severity}</span>
}

export function StatusBadge({ status }) {
  const label = { new: 'New', open: 'Investigating', resolved: 'Resolved' }[status]
  return <span className={`status-badge st-${status}`}>{label}</span>
}

export function formatCountdown(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000))
  const m = Math.floor(s / 60)
  return `${m}:${String(s % 60).padStart(2, '0')}`
}

export function formatClock(ts) {
  const d = new Date(ts)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

export function slaRemaining(alert, now) {
  if (alert.status !== 'open' || !alert.openedAt) return null
  return alert.slaSeconds * 1000 - (now - alert.openedAt)
}

export function SlaTimer({ alert, now }) {
  const rem = slaRemaining(alert, now)
  if (rem == null) return <span className="sla-idle">not started</span>
  const cls = rem < 30000 ? 'sla-critical' : rem < 75000 ? 'sla-warning' : 'sla-ok'
  return <span className={`sla-timer ${cls}`}>{formatCountdown(rem)}</span>
}
