import { Mail, MailOpen, FileBarChart2 } from 'lucide-react'
import { useGame } from '../game/GameContext.jsx'
import { formatClock } from './ui.jsx'

export default function Inbox() {
  const { state, dispatch } = useGame()
  const emails = [...state.emails].reverse()
  const selected = state.emails.find((e) => e.id === state.selectedEmail)

  return (
    <div className="inbox">
      <div className="page-head">
        <h2>Inbox</h2>
        <span className="queue-hint">{state.emails.filter((e) => !e.read).length} unread</span>
      </div>
      <div className="inbox-grid">
        <ul className="email-list">
          {emails.map((e) => (
            <li key={e.id}>
              <button
                className={`email-item ${e.read ? '' : 'email-unread'} ${state.selectedEmail === e.id ? 'email-selected' : ''}`}
                onClick={() => dispatch({ type: 'OPEN_EMAIL', id: e.id })}
              >
                {e.read ? <MailOpen size={15} /> : <Mail size={15} />}
                <span className="email-meta">
                  <span className="email-from">{e.from.name}</span>
                  <span className="email-subject">{e.subject}</span>
                </span>
                <span className="email-time mono">{formatClock(e.receivedAt)}</span>
              </button>
            </li>
          ))}
        </ul>

        <div className="email-reader">
          {selected ? (
            <>
              <div className="email-head">
                <h3>{selected.subject}</h3>
                <p className="email-sender">
                  <strong>{selected.from.name}</strong> · {selected.from.role}
                  <span className="mono email-addr"> &lt;{selected.from.addr}&gt;</span>
                </p>
              </div>
              <div className="email-body">{selected.body}</div>
              {selected.kind.startsWith('final-') && (
                <button className="btn btn-primary" onClick={() => dispatch({ type: 'SHOW_REPORT' })}>
                  <FileBarChart2 size={16} /> View shift report
                </button>
              )}
            </>
          ) : (
            <p className="empty-note">Select a message to read it.</p>
          )}
        </div>
      </div>
    </div>
  )
}
