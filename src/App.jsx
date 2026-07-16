import { useGame } from './game/GameContext.jsx'
import IntroScreen from './components/IntroScreen.jsx'
import Sidebar from './components/Sidebar.jsx'
import TopBar from './components/TopBar.jsx'
import Dashboard from './components/Dashboard.jsx'
import AlertQueue from './components/AlertQueue.jsx'
import Inbox from './components/Inbox.jsx'
import ReportModal from './components/ReportModal.jsx'
import Toasts from './components/Toasts.jsx'

export default function App() {
  const { state } = useGame()

  if (state.phase === 'intro') return <IntroScreen />

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-main">
        <TopBar />
        <main className="app-content">
          {state.view === 'dashboard' && <Dashboard />}
          {state.view === 'queue' && <AlertQueue />}
          {state.view === 'inbox' && <Inbox />}
        </main>
      </div>
      {state.showReport && <ReportModal />}
      <Toasts />
    </div>
  )
}
