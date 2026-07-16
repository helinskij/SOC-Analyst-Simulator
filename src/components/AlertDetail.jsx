import { useState } from 'react'
import { ArrowLeft, CheckCircle2, XCircle, TerminalSquare, Database, Send } from 'lucide-react'
import { useGame } from '../game/GameContext.jsx'
import { SeverityBadge, SlaTimer } from './ui.jsx'
import { CATEGORIES } from '../data/templates.js'

export default function AlertDetail({ alert }) {
  const { state, dispatch } = useGame()
  const [verdict, setVerdict] = useState(null)
  const [category, setCategory] = useState('')
  const [action, setAction] = useState(null)

  const resolution = state.resolutions[alert.uid]
  const isResolved = alert.status === 'resolved'
  const canSubmit = verdict === 'fp' || (verdict === 'tp' && category && action)

  const submit = () => {
    if (!canSubmit) return
    dispatch({
      type: 'RESOLVE_ALERT',
      uid: alert.uid,
      decision: { verdict, category: verdict === 'tp' ? category : null, action: verdict === 'tp' ? action : 'close' },
    })
  }

  return (
    <div className="alert-detail">
      <div className="detail-topline">
        <button className="btn btn-ghost" onClick={() => dispatch({ type: 'CLOSE_DETAIL' })}>
          <ArrowLeft size={15} /> Queue
        </button>
        {!isResolved && (
          <div className="detail-sla">
            SLA <SlaTimer alert={alert} now={state.now} />
          </div>
        )}
      </div>

      <div className="detail-header">
        <div className="detail-idline">
          <span className="mono detail-number">{alert.number}</span>
          <SeverityBadge severity={alert.severity} />
          <span className="detail-source">{alert.source}</span>
          <span className="detail-fired mono">fired {alert.firedAt}</span>
        </div>
        <h2 className="detail-title">{alert.title}</h2>
        <p className="detail-rule mono">Rule: {alert.ruleName}</p>
      </div>

      <div className="detail-grid">
        <div className="detail-main">
          <section className="panel">
            <h3 className="panel-title">Alert summary</h3>
            <p className="detail-desc">{alert.description}</p>
          </section>

          <section className="panel">
            <h3 className="panel-title"><TerminalSquare size={15} /> Event log excerpt</h3>
            <div className="log-block">
              {alert.logs.map((line, i) => <div key={i} className="log-line">{line}</div>)}
            </div>
          </section>

          <section className="panel">
            <h3 className="panel-title"><Database size={15} /> Enrichment</h3>
            <table className="enrich-table">
              <tbody>
                {alert.enrichment.map((e, i) => (
                  <tr key={i}>
                    <td className="enrich-label">{e.label}</td>
                    <td className={`enrich-value ${e.tone ? `tone-${e.tone}` : ''}`}>{e.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>

        <aside className="detail-side">
          {isResolved ? <ResolutionSummary alert={alert} resolution={resolution} /> : (
            <section className="panel triage-panel">
              <h3 className="panel-title">Triage decision</h3>

              <div className="form-group">
                <span className="form-label">1 · Verdict</span>
                <div className="choice-col">
                  <button className={`choice ${verdict === 'tp' ? 'choice-active choice-tp' : ''}`} onClick={() => setVerdict('tp')}>
                    True Positive
                    <small>Real malicious or policy-violating activity</small>
                  </button>
                  <button className={`choice ${verdict === 'fp' ? 'choice-active choice-fp' : ''}`} onClick={() => setVerdict('fp')}>
                    False Positive
                    <small>Benign activity that tripped a detection rule</small>
                  </button>
                </div>
              </div>

              {verdict === 'tp' && (
                <>
                  <div className="form-group">
                    <label className="form-label" htmlFor="cat-select">2 · Attack category</label>
                    <select id="cat-select" className="cat-select" value={category} onChange={(e) => setCategory(e.target.value)}>
                      <option value="">— classify the attack —</option>
                      {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </div>
                  <div className="form-group">
                    <span className="form-label">3 · Response action</span>
                    <div className="choice-col">
                      <button className={`choice ${action === 'escalate' ? 'choice-active choice-esc' : ''}`} onClick={() => setAction('escalate')}>
                        Escalate to L2
                        <small>Confirmed / active compromise needing response</small>
                      </button>
                      <button className={`choice ${action === 'close' ? 'choice-active choice-cls' : ''}`} onClick={() => setAction('close')}>
                        Close — documented
                        <small>Real attempt, fully blocked, no success indicators</small>
                      </button>
                    </div>
                  </div>
                </>
              )}

              {verdict === 'fp' && (
                <div className="form-group">
                  <span className="form-label">2 · Response action</span>
                  <div className="choice choice-active choice-cls choice-static">
                    Close — false positive
                    <small>Benign alerts are closed with a tuning note</small>
                  </div>
                </div>
              )}

              <button className="btn btn-primary btn-block" disabled={!canSubmit} onClick={submit}>
                <Send size={15} /> Submit resolution
              </button>
            </section>
          )}
        </aside>
      </div>
    </div>
  )
}

function ResolutionSummary({ alert, resolution: r }) {
  if (!r) return null
  const rows = r.slaBreached
    ? []
    : [
        {
          label: 'Verdict',
          yours: r.verdict === 'tp' ? 'True Positive' : 'False Positive',
          actual: alert.verdict === 'tp' ? 'True Positive' : 'False Positive',
          ok: r.verdictOk,
        },
        ...(alert.verdict === 'tp' && r.verdict === 'tp'
          ? [
              { label: 'Category', yours: CATEGORIES[r.category] || '—', actual: CATEGORIES[alert.category], ok: r.categoryOk },
              { label: 'Action', yours: r.action === 'escalate' ? 'Escalate' : 'Close', actual: alert.correctAction === 'escalate' ? 'Escalate' : 'Close', ok: r.actionOk },
            ]
          : []),
      ]

  return (
    <section className={`panel triage-panel result-panel ${r.correct ? 'result-good' : 'result-bad'}`}>
      <h3 className="panel-title">
        {r.slaBreached
          ? <><XCircle size={16} /> SLA breached</>
          : r.correct
            ? <><CheckCircle2 size={16} /> Resolved correctly</>
            : <><XCircle size={16} /> Resolved incorrectly</>}
      </h3>
      {r.slaBreached && (
        <p className="result-note">The SLA clock expired before a decision was submitted. The alert was auto-failed and counted against your accuracy.</p>
      )}
      {rows.map((row) => (
        <div key={row.label} className="result-row">
          <span className="result-label">{row.label}</span>
          <span className={`result-val ${row.ok ? 'tone-ok' : 'tone-bad'}`}>
            {row.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />} {row.yours}
          </span>
          {!row.ok && <span className="result-actual">correct: {row.actual}</span>}
        </div>
      ))}
      <div className="result-explain">
        <h4>Analyst notes</h4>
        <p>{alert.explanation}</p>
      </div>
    </section>
  )
}
