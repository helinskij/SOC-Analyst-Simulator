import { Activity, CheckCircle2, Target } from 'lucide-react'
import { useGame, computeStats } from '../game/GameContext.jsx'

export default function TopBar() {
  const { state } = useGame()
  const stats = computeStats(state)
  const pct = Math.round(stats.accuracy * 100)

  return (
    <header className="topbar">
      <div className="topbar-status">
        <span className="live-dot" aria-hidden="true" />
        <span className="topbar-label">SHIFT IN PROGRESS</span>
      </div>
      <div className="topbar-metrics">
        <span className="topbar-metric" title="Alerts resolved">
          <CheckCircle2 size={15} /> {stats.resolved}/{stats.total} resolved
        </span>
        <span className="topbar-metric" title="Resolution accuracy">
          <Target size={15} /> {stats.resolved ? `${pct}% accuracy` : '— accuracy'}
        </span>
        <span className="topbar-metric" title="Current correct streak">
          <Activity size={15} /> streak {stats.streak}
        </span>
      </div>
    </header>
  )
}
