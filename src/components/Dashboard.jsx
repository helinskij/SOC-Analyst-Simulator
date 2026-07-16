import { Bell, CheckCircle2, Clock3, Flame, ShieldAlert, Timer } from 'lucide-react'
import { useGame, computeStats } from '../game/GameContext.jsx'
import { CATEGORIES } from '../data/templates.js'

function StatCard({ icon: Icon, label, value, sub, tone }) {
  return (
    <div className={`stat-card ${tone ? `stat-${tone}` : ''}`}>
      <div className="stat-head">
        <Icon size={16} strokeWidth={1.8} />
        <span>{label}</span>
      </div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export default function Dashboard() {
  const { state, dispatch } = useGame()
  const stats = computeStats(state)

  const accuracyPct = stats.resolved ? Math.round(stats.accuracy * 100) : null
  const slaPct = stats.resolved ? Math.round(stats.slaCompliance * 100) : null
  const avg = stats.avgTime
    ? `${Math.floor(stats.avgTime / 60)}:${String(Math.round(stats.avgTime % 60)).padStart(2, '0')}`
    : '—'

  // True positives resolved so far, grouped by actual category
  const byCategory = Object.keys(CATEGORIES).map((key) => {
    const done = state.alerts.filter(
      (a) => a.verdict === 'tp' && a.category === key && state.resolutions[a.uid],
    )
    return {
      key,
      name: CATEGORIES[key],
      total: done.length,
      correct: done.filter((a) => state.resolutions[a.uid].correct).length,
    }
  }).filter((c) => c.total > 0)

  const maxCat = Math.max(1, ...byCategory.map((c) => c.total))
  const openCount = state.alerts.slice(0, state.revealedCount).filter((a) => a.status !== 'resolved').length
  const threat = state.alerts.slice(0, state.revealedCount).some((a) => a.tier === 3)
    ? { label: 'ELEVATED', cls: 'threat-high' }
    : state.alerts.slice(0, state.revealedCount).some((a) => a.tier === 2)
      ? { label: 'GUARDED', cls: 'threat-med' }
      : { label: 'NOMINAL', cls: 'threat-low' }

  return (
    <div className="dashboard">
      <div className="page-head">
        <h2>Shift Overview</h2>
        <div className={`threat-pill ${threat.cls}`}>
          <ShieldAlert size={14} /> Threat level: {threat.label}
        </div>
      </div>

      <div className="stat-grid">
        <StatCard icon={CheckCircle2} label="Alerts resolved" value={`${stats.resolved}/${stats.total}`}
          sub={`${openCount} waiting in queue`} />
        <StatCard icon={Flame} label="Resolution accuracy" value={accuracyPct == null ? '—' : `${accuracyPct}%`}
          sub={`${stats.correct} fully correct`} tone={accuracyPct == null ? null : accuracyPct >= 90 ? 'good' : accuracyPct >= 75 ? 'warn' : 'bad'} />
        <StatCard icon={Timer} label="SLA compliance" value={slaPct == null ? '—' : `${slaPct}%`}
          sub={`${stats.slaBreaches} breach${stats.slaBreaches === 1 ? '' : 'es'}`} tone={slaPct == null ? null : slaPct === 100 ? 'good' : slaPct >= 90 ? 'warn' : 'bad'} />
        <StatCard icon={Clock3} label="Avg. handle time" value={avg} sub="per resolved alert" />
      </div>

      <div className="dash-columns">
        <section className="panel">
          <h3 className="panel-title">Verdict performance</h3>
          <div className="verdict-rows">
            <div className="verdict-row">
              <span className="verdict-label">True positives identified</span>
              <div className="meter"><div className="meter-fill meter-red"
                style={{ width: stats.tpHandled ? `${(stats.tpCaught / stats.tpHandled) * 100}%` : 0 }} /></div>
              <span className="verdict-count">{stats.tpCaught}/{stats.tpHandled}</span>
            </div>
            <div className="verdict-row">
              <span className="verdict-label">False positives identified</span>
              <div className="meter"><div className="meter-fill meter-blue"
                style={{ width: stats.fpHandled ? `${(stats.fpCaught / stats.fpHandled) * 100}%` : 0 }} /></div>
              <span className="verdict-count">{stats.fpCaught}/{stats.fpHandled}</span>
            </div>
          </div>
          <h3 className="panel-title" style={{ marginTop: 24 }}>Attack categories triaged</h3>
          {byCategory.length === 0 ? (
            <p className="empty-note">No true positives resolved yet — get to the queue.</p>
          ) : (
            <div className="cat-bars">
              {byCategory.map((c) => (
                <div key={c.key} className="cat-row">
                  <span className="cat-name">{c.name}</span>
                  <div className="meter">
                    <div className="meter-fill meter-cyan" style={{ width: `${(c.total / maxCat) * 100}%` }} />
                  </div>
                  <span className="cat-count">{c.correct}/{c.total} correct</span>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="panel">
          <h3 className="panel-title">Shift progress</h3>
          <div className="progress-wrap">
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${(stats.resolved / stats.total) * 100}%` }} />
            </div>
            <span className="progress-label">{Math.round((stats.resolved / stats.total) * 100)}% of the night's queue cleared</span>
          </div>
          <div className="dash-hints">
            <p><strong>Performance targets</strong> (reviewed by your manager at 06:00):</p>
            <ul>
              <li>100% accuracy — flawless shift, word is there's an L2 seat open…</li>
              <li>≥ 75% accuracy — acceptable performance</li>
              <li>&lt; 75% accuracy — a conversation with HR</li>
            </ul>
          </div>
          {openCount > 0 && (
            <button className="btn btn-primary btn-block" onClick={() => dispatch({ type: 'SET_VIEW', view: 'queue' })}>
              <Bell size={16} /> Work the queue ({openCount} waiting)
            </button>
          )}
        </section>
      </div>
    </div>
  )
}
