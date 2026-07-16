import { Award, ThumbsUp, DoorOpen, RotateCcw, ExternalLink, X } from 'lucide-react'
import { useGame, computeStats } from '../game/GameContext.jsx'

export default function ReportModal() {
  const { state, dispatch } = useGame()
  const stats = computeStats(state)
  const pct = Math.round(stats.accuracy * 100)

  const grade = stats.accuracy >= 1
    ? { icon: Award, title: 'PROMOTED TO L2 ANALYST', cls: 'grade-gold', text: 'A flawless shift — every verdict, classification and routing decision correct. Welcome to incident response.' }
    : stats.accuracy >= 0.75
      ? { icon: ThumbsUp, title: 'SHIFT PASSED', cls: 'grade-pass', text: 'A solid night on the queue. Review the misses in your inbox and come back sharper — L2 is within reach.' }
      : { icon: DoorOpen, title: 'TERMINATED', cls: 'grade-fail', text: 'Too many real incidents slipped through. Security operations wasn\'t the right fit — this time.' }

  const Icon = grade.icon
  const mins = state.endedAt && state.startedAt ? Math.round((state.endedAt - state.startedAt) / 60000) : null

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Shift report">
      <div className="modal report-modal">
        <button className="modal-close" aria-label="Close report" onClick={() => dispatch({ type: 'HIDE_REPORT' })}>
          <X size={18} />
        </button>
        <div className={`grade-banner ${grade.cls}`}>
          <Icon size={30} strokeWidth={1.6} />
          <h2>{grade.title}</h2>
          <p>{grade.text}</p>
        </div>

        <div className="report-stats">
          <div className="report-stat"><span className="report-num">{pct}%</span><span>accuracy</span></div>
          <div className="report-stat"><span className="report-num">{stats.correct}/{stats.resolved}</span><span>fully correct</span></div>
          <div className="report-stat"><span className="report-num">{stats.tpCaught}/{stats.tpHandled}</span><span>true positives caught</span></div>
          <div className="report-stat"><span className="report-num">{stats.fpCaught}/{stats.fpHandled}</span><span>false positives spotted</span></div>
          <div className="report-stat"><span className="report-num">{stats.slaBreaches}</span><span>SLA breaches</span></div>
          <div className="report-stat"><span className="report-num">{mins ?? '—'}{mins != null && 'm'}</span><span>shift length</span></div>
        </div>

        <div className="report-outro">
          <p><strong>Thanks for playing SOC Analyst Simulator.</strong></p>
          <p>
            Every alert in this game is modeled on real detection scenarios — and so are the
            false positives, because knowing what <em>not</em> to escalate is half the job.
          </p>
          <p>
            More projects like this one:{' '}
            <a href="https://jakubhelinski.com" target="_blank" rel="noreferrer">
              jakubhelinski.com <ExternalLink size={12} />
            </a>
          </p>
        </div>

        <div className="report-actions">
          <button className="btn btn-primary" onClick={() => dispatch({ type: 'RESTART' })}>
            <RotateCcw size={15} /> Play again — new random shift
          </button>
        </div>
      </div>
    </div>
  )
}
