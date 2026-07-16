import { createContext, useContext, useEffect, useReducer } from 'react'
import { generateRun } from './generator.js'
import { saveGame, loadGame, clearSave } from './storage.js'
import {
  briefingEmail, mistakeEmail, praiseEmail, tier2Email, tier3Email,
  coffeeEmail, finalEmail,
} from '../data/emails.js'

const GameContext = createContext(null)

const INITIAL_REVEALED = 3
const PRAISE_STREAKS = [6, 14]

const initialState = {
  phase: 'intro', // intro | playing | ended
  alerts: [],
  revealedCount: 0,
  resolutions: {}, // uid -> resolution record
  emails: [],
  view: 'dashboard', // dashboard | queue | inbox
  selectedAlert: null,
  selectedEmail: null,
  streak: 0,
  praised: [],
  sentTier2: false,
  sentTier3: false,
  sentCoffee: false,
  startedAt: null,
  endedAt: null,
  showReport: false,
  now: Date.now(),
}

export function computeStats(state) {
  const records = Object.values(state.resolutions)
  const resolved = records.length
  const correct = records.filter((r) => r.correct).length
  const slaBreaches = records.filter((r) => r.slaBreached).length
  const tpHandled = records.filter((r) => r.actualVerdict === 'tp').length
  const tpCaught = records.filter((r) => r.actualVerdict === 'tp' && r.verdictOk).length
  const fpHandled = records.filter((r) => r.actualVerdict === 'fp').length
  const fpCaught = records.filter((r) => r.actualVerdict === 'fp' && r.verdictOk).length
  const timed = records.filter((r) => !r.slaBreached && r.timeSpent != null)
  const avgTime = timed.length ? timed.reduce((s, r) => s + r.timeSpent, 0) / timed.length : 0
  return {
    total: state.alerts.length,
    resolved,
    correct,
    accuracy: resolved ? correct / resolved : 0,
    slaBreaches,
    slaCompliance: resolved ? (resolved - slaBreaches) / resolved : 1,
    tpHandled, tpCaught, fpHandled, fpCaught,
    avgTime,
    streak: state.streak,
  }
}

function scoreResolution(alert, { verdict, category, action }, slaBreached, timeSpent) {
  if (slaBreached) {
    return {
      verdict: null, category: null, action: null,
      actualVerdict: alert.verdict,
      verdictOk: false, categoryOk: false, actionOk: false,
      correct: false, slaBreached: true, timeSpent: null,
    }
  }
  const verdictOk = verdict === alert.verdict
  const categoryOk = alert.verdict === 'fp' ? true : category === alert.category
  const actionOk = alert.verdict === 'fp' ? true : action === alert.correctAction
  return {
    verdict, category, action,
    actualVerdict: alert.verdict,
    verdictOk, categoryOk, actionOk,
    correct: verdictOk && categoryOk && actionOk,
    slaBreached: false, timeSpent,
  }
}

// Shared logic for a resolved alert (player action or SLA breach)
function applyResolution(state, alertId, res) {
  const alerts = state.alerts.map((a) => (a.uid === alertId ? { ...a, status: 'resolved' } : a))
  const alert = state.alerts.find((a) => a.uid === alertId)
  const resolutions = { ...state.resolutions, [alertId]: res }
  const emails = [...state.emails]
  let { streak, praised, sentTier2, sentTier3, sentCoffee } = state

  if (res.correct) {
    streak += 1
    if (PRAISE_STREAKS.includes(streak) && !praised.includes(streak)) {
      praised = [...praised, streak]
      emails.push(praiseEmail(streak))
    }
  } else {
    streak = 0
    emails.push(mistakeEmail(alert, res))
  }

  // Reveal the next alert in the queue
  const revealedCount = Math.min(state.revealedCount + 1, alerts.length)

  // Flavor emails on tier transitions / mid-shift
  const revealed = alerts.slice(0, revealedCount)
  if (!sentTier2 && revealed.some((a) => a.tier === 2)) {
    sentTier2 = true
    emails.push(tier2Email())
  }
  if (!sentTier3 && revealed.some((a) => a.tier === 3)) {
    sentTier3 = true
    emails.push(tier3Email())
  }
  const resolvedCount = Object.keys(resolutions).length
  if (!sentCoffee && resolvedCount === 10) {
    sentCoffee = true
    emails.push(coffeeEmail())
  }

  let phase = state.phase
  let endedAt = state.endedAt
  if (resolvedCount >= alerts.length) {
    phase = 'ended'
    endedAt = Date.now()
    const stats = computeStats({ ...state, alerts, resolutions })
    emails.push(finalEmail(stats.accuracy, stats))
  }

  return {
    ...state,
    alerts, resolutions, emails, streak, praised,
    sentTier2, sentTier3, sentCoffee, phase, endedAt,
    revealedCount,
    selectedAlert: null,
  }
}

function reducer(state, action) {
  switch (action.type) {
    case 'START_GAME': {
      return {
        ...initialState,
        phase: 'playing',
        alerts: generateRun(),
        revealedCount: INITIAL_REVEALED,
        emails: [briefingEmail()],
        view: 'inbox',
        startedAt: Date.now(),
        now: Date.now(),
      }
    }
    case 'RESUME_GAME':
      return { ...state, ...action.state, now: Date.now() }
    case 'SET_VIEW':
      return { ...state, view: action.view, selectedAlert: null, selectedEmail: null }
    case 'OPEN_ALERT': {
      const alerts = state.alerts.map((a) =>
        a.uid === action.uid && a.status === 'new'
          ? { ...a, status: 'open', openedAt: Date.now() }
          : a,
      )
      return { ...state, alerts, selectedAlert: action.uid, view: 'queue' }
    }
    case 'CLOSE_DETAIL':
      return { ...state, selectedAlert: null }
    case 'OPEN_EMAIL': {
      const emails = state.emails.map((e) => (e.id === action.id ? { ...e, read: true } : e))
      return { ...state, emails, selectedEmail: action.id }
    }
    case 'CLOSE_EMAIL':
      return { ...state, selectedEmail: null }
    case 'RESOLVE_ALERT': {
      const alert = state.alerts.find((a) => a.uid === action.uid)
      if (!alert || alert.status === 'resolved') return state
      const timeSpent = alert.openedAt ? (Date.now() - alert.openedAt) / 1000 : 0
      const res = scoreResolution(alert, action.decision, false, timeSpent)
      return applyResolution(state, action.uid, res)
    }
    case 'SLA_BREACH': {
      const alert = state.alerts.find((a) => a.uid === action.uid)
      if (!alert || alert.status === 'resolved') return state
      const res = scoreResolution(alert, {}, true, null)
      return applyResolution(state, action.uid, res)
    }
    case 'TICK':
      return { ...state, now: Date.now() }
    case 'SHOW_REPORT':
      return { ...state, showReport: true }
    case 'HIDE_REPORT':
      return { ...state, showReport: false }
    case 'RESTART':
      clearSave()
      return { ...initialState, now: Date.now() }
    default:
      return state
  }
}

export function GameProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState)

  // 1s tick drives SLA countdowns; breaches auto-resolve the alert
  useEffect(() => {
    if (state.phase !== 'playing') return
    const t = setInterval(() => dispatch({ type: 'TICK' }), 1000)
    return () => clearInterval(t)
  }, [state.phase])

  useEffect(() => {
    if (state.phase !== 'playing') return
    for (const a of state.alerts) {
      if (a.status === 'open' && a.openedAt && state.now - a.openedAt > a.slaSeconds * 1000) {
        dispatch({ type: 'SLA_BREACH', uid: a.uid })
      }
    }
  }, [state.now, state.phase, state.alerts])

  // Persist progress so an accidental tab close doesn't wipe the run
  useEffect(() => {
    if (state.phase === 'playing' || state.phase === 'ended') saveGame(state)
  }, [state.alerts, state.resolutions, state.emails, state.phase, state.view,
      state.selectedAlert, state.selectedEmail, state.showReport])

  return <GameContext.Provider value={{ state, dispatch }}>{children}</GameContext.Provider>
}

export function useGame() {
  return useContext(GameContext)
}

export { loadGame }
