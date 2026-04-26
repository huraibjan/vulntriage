import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Vulnerabilities from './pages/Vulnerabilities'
import VulnDetail from './pages/VulnDetail'

export default function App() {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/vuln/:id" element={<VulnDetail />} />
        </Routes>
      </main>
    </div>
  )
}
