import { LayoutDashboard, Bell, Mail, ShieldCheck } from 'lucide-react'
import { useGame } from '../game/GameContext.jsx'

export default function Sidebar() {
  const { state, dispatch } = useGame()
  const unreadEmails = state.emails.filter((e) => !e.read).length
  const openAlerts = state.alerts.slice(0, state.revealedCount).filter((a) => a.status !== 'resolved').length

  const items = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, badge: 0 },
    { id: 'queue', label: 'Alert Queue', icon: Bell, badge: openAlerts },
    { id: 'inbox', label: 'Inbox', icon: Mail, badge: unreadEmails },
  ]

  return (
    <nav className="sidebar">
      <div className="sidebar-brand">
        <ShieldCheck size={24} strokeWidth={1.6} />
        <div>
          <span className="brand-name">NORTHBRIDGE</span>
          <span className="brand-sub">SOC Console v4.2</span>
        </div>
      </div>
      <ul className="sidebar-nav">
        {items.map(({ id, label, icon: Icon, badge }) => (
          <li key={id}>
            <button
              className={`nav-item ${state.view === id ? 'active' : ''}`}
              onClick={() => dispatch({ type: 'SET_VIEW', view: id })}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
              {badge > 0 && <span className="nav-badge">{badge}</span>}
            </button>
          </li>
        ))}
      </ul>
      <div className="sidebar-footer">
        <div className="analyst-chip">
          <div className="analyst-avatar">L1</div>
          <div>
            <span className="analyst-name">You</span>
            <span className="analyst-role">Tier 1 Analyst · Night</span>
          </div>
        </div>
      </div>
    </nav>
  )
}
