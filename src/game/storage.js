const KEY = 'soc-analyst-simulator-save-v1'

export function saveGame(state) {
  try {
    const { now, ...rest } = state
    localStorage.setItem(KEY, JSON.stringify({ ...rest, savedAt: Date.now() }))
  } catch {
    // storage full/unavailable — the game keeps working without saves
  }
}

export function loadGame() {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return null
    const state = JSON.parse(raw)
    if (!state || state.phase === 'intro') return null
    // Pause credit: shift open-alert SLA clocks by the time spent away,
    // so closing the tab doesn't burn the timers.
    const away = Date.now() - (state.savedAt || Date.now())
    if (away > 0 && Array.isArray(state.alerts)) {
      state.alerts = state.alerts.map((a) =>
        a.status === 'open' && a.openedAt ? { ...a, openedAt: a.openedAt + away } : a,
      )
    }
    delete state.savedAt
    return state
  } catch {
    return null
  }
}

export function clearSave() {
  try {
    localStorage.removeItem(KEY)
  } catch {
    /* ignore */
  }
}
