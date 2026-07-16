import { useEffect, useRef, useState } from 'react'
import { Mail, X } from 'lucide-react'
import { useGame } from '../game/GameContext.jsx'

const TOAST_LIFETIME = 7000
const MAX_VISIBLE = 3

export default function Toasts() {
  const { state, dispatch } = useGame()
  const [toasts, setToasts] = useState([])
  const seen = useRef(new Set())
  const prevPhase = useRef(state.phase)

  useEffect(() => {
    const cameFromIntro = prevPhase.current === 'intro' && state.phase !== 'intro'
    prevPhase.current = state.phase

    const fresh = state.emails.filter((e) => !seen.current.has(e.id))
    fresh.forEach((e) => seen.current.add(e.id))

    // Don't toast the opening briefing / a resumed game's backlog,
    // and don't toast while the user is already looking at the inbox.
    if (cameFromIntro || state.view === 'inbox' || fresh.length === 0) return

    setToasts((t) => [
      ...t,
      ...fresh.map((e) => ({ id: e.id, from: e.from.name, role: e.from.role, subject: e.subject })),
    ])
  }, [state.emails, state.phase, state.view])

  const dismiss = (id) => setToasts((t) => t.filter((x) => x.id !== id))

  const open = (id) => {
    dismiss(id)
    dispatch({ type: 'SET_VIEW', view: 'inbox' })
    dispatch({ type: 'OPEN_EMAIL', id })
  }

  return (
    <div className="toast-stack" aria-live="polite">
      {toasts.slice(-MAX_VISIBLE).map((t) => (
        <Toast key={t.id} toast={t} onOpen={() => open(t.id)} onDismiss={() => dismiss(t.id)} />
      ))}
    </div>
  )
}

function Toast({ toast, onOpen, onDismiss }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, TOAST_LIFETIME)
    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="toast" role="status">
      <button className="toast-body" onClick={onOpen} title="Open in inbox">
        <Mail size={16} />
        <span className="toast-text">
          <span className="toast-from">New email — {toast.from} <em>({toast.role})</em></span>
          <span className="toast-subject">{toast.subject}</span>
        </span>
      </button>
      <button className="toast-close" aria-label="Dismiss notification" onClick={onDismiss}>
        <X size={14} />
      </button>
    </div>
  )
}
