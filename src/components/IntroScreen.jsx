import { useState } from 'react'
import { ShieldCheck, Clock3, ListChecks, MailWarning, Play, RotateCcw } from 'lucide-react'
import { useGame, loadGame } from '../game/GameContext.jsx'

export default function IntroScreen() {
  const { dispatch } = useGame()
  const [saved] = useState(() => loadGame())

  return (
    <div className="intro-screen">
      <div className="intro-card">
        <div className="intro-logo">
          <ShieldCheck size={34} strokeWidth={1.6} />
          <div>
            <h1>SOC Analyst Simulator</h1>
            <p className="intro-sub">Northbridge Financial — Security Operations Center</p>
          </div>
        </div>

        <p className="intro-lede">
          You are the <strong>L1 analyst on tonight's shift</strong>. Alerts from the SIEM land in
          your queue — some are real attacks, some are just the business doing business.
          Your job is to tell them apart, fast.
        </p>

        <div className="intro-grid">
          <div className="intro-item">
            <ListChecks size={20} strokeWidth={1.8} />
            <div>
              <h3>Triage every alert</h3>
              <p>Read the logs and enrichment, then decide: <strong>true positive</strong> or{' '}
              <strong>false positive</strong>? If it's real — classify the attack and choose
              whether to <strong>escalate</strong> it to L2 or <strong>close</strong> it as a blocked attempt.</p>
            </div>
          </div>
          <div className="intro-item">
            <Clock3 size={20} strokeWidth={1.8} />
            <div>
              <h3>Beat the SLA</h3>
              <p>Opening an alert starts its SLA countdown. Run out of time and the alert
              auto-fails — so don't open what you're not ready to work.</p>
            </div>
          </div>
          <div className="intro-item">
            <MailWarning size={20} strokeWidth={1.8} />
            <div>
              <h3>Watch your inbox</h3>
              <p>Your manager and the L2 team follow your work. Mistakes come back as feedback
              emails — and your performance decides how the shift ends.</p>
            </div>
          </div>
        </div>

        <p className="intro-note">
          ~24 alerts · difficulty ramps up as the night goes on · roughly 45–60 minutes ·
          progress is saved locally in your browser
        </p>

        <div className="intro-actions">
          {saved && (
            <button
              className="btn btn-secondary"
              onClick={() => dispatch({ type: 'RESUME_GAME', state: saved })}
            >
              <RotateCcw size={16} /> Resume previous shift
            </button>
          )}
          <button className="btn btn-primary" onClick={() => dispatch({ type: 'START_GAME' })}>
            <Play size={16} /> {saved ? 'Start a new shift' : 'Clock in — start shift'}
          </button>
        </div>
      </div>
      <p className="intro-footer">
        A browser game about alert triage · no accounts, no data leaves your machine ·{' '}
        <a href="https://jakubhelinski.com" target="_blank" rel="noreferrer">jakubhelinski.com</a>
      </p>
    </div>
  )
}
