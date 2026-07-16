import { useGame } from '../game/GameContext.jsx'
import { SeverityBadge, StatusBadge, SlaTimer } from './ui.jsx'
import AlertDetail from './AlertDetail.jsx'
import { CheckCircle2, XCircle, Search } from 'lucide-react'

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

export default function AlertQueue() {
  const { state, dispatch } = useGame()

  if (state.selectedAlert) {
    const alert = state.alerts.find((a) => a.uid === state.selectedAlert)
    if (alert) return <AlertDetail alert={alert} />
  }

  const revealed = state.alerts.slice(0, state.revealedCount)
  const active = revealed
    .filter((a) => a.status !== 'resolved')
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
  const resolved = revealed.filter((a) => a.status === 'resolved').reverse()

  return (
    <div className="queue">
      <div className="page-head">
        <h2>Alert Queue</h2>
        <span className="queue-hint">Opening an alert starts its SLA clock — triage what you open.</span>
      </div>

      <table className="alert-table">
        <thead>
          <tr>
            <th>ID</th><th>Severity</th><th>Alert</th><th>Source</th><th>Entity</th>
            <th>Status</th><th>SLA</th><th aria-label="action" />
          </tr>
        </thead>
        <tbody>
          {active.length === 0 && (
            <tr><td colSpan={8} className="empty-row">
              {resolved.length === state.alerts.length
                ? 'Queue clear — check your inbox.'
                : 'Queue clear for now…'}
            </td></tr>
          )}
          {active.map((a) => (
            <tr key={a.uid} className={`alert-row ${a.status === 'open' ? 'row-open' : ''}`}
              onClick={() => dispatch({ type: 'OPEN_ALERT', uid: a.uid })}>
              <td className="mono">{a.number}</td>
              <td><SeverityBadge severity={a.severity} /></td>
              <td className="alert-title-cell">
                <span className="alert-rule">{a.ruleName}</span>
                <span className="alert-title">{a.title}</span>
              </td>
              <td>{a.source}</td>
              <td className="mono">{a.entity}</td>
              <td><StatusBadge status={a.status} /></td>
              <td className="mono"><SlaTimer alert={a} now={state.now} /></td>
              <td>
                <button className="btn btn-small" onClick={(e) => { e.stopPropagation(); dispatch({ type: 'OPEN_ALERT', uid: a.uid }) }}>
                  <Search size={13} /> {a.status === 'open' ? 'Resume' : 'Investigate'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {resolved.length > 0 && (
        <>
          <h3 className="section-label">Resolved this shift</h3>
          <table className="alert-table resolved-table">
            <tbody>
              {resolved.map((a) => {
                const r = state.resolutions[a.uid]
                return (
                  <tr key={a.uid} className="alert-row row-resolved" onClick={() => dispatch({ type: 'OPEN_ALERT', uid: a.uid })}>
                    <td className="mono">{a.number}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="alert-title-cell"><span className="alert-title">{a.title}</span></td>
                    <td className="mono">
                      {r?.slaBreached
                        ? <span className="res-tag res-bad"><XCircle size={13} /> SLA breach</span>
                        : r?.correct
                          ? <span className="res-tag res-good"><CheckCircle2 size={13} /> Correct</span>
                          : <span className="res-tag res-bad"><XCircle size={13} /> Incorrect</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
