import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import CBOMPage from './pages/CBOM.jsx'
import AlertsPage from './pages/Alerts.jsx'
import ThreatIntelPage from './pages/ThreatIntel.jsx'
import MLPage from './pages/MLDetection.jsx'
import NetworkPage from './pages/Network.jsx'
import { getToken } from './utils/api.js'

function PrivateRoute({ children }) {
  return getToken() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="cbom" element={<CBOMPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="ml" element={<MLPage />} />
          <Route path="network" element={<NetworkPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
