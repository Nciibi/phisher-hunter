import { Routes, Route } from 'react-router-dom'
import MainPage from './pages/Main'
import DetailsPage from './pages/Details'
import SettingsPage from './pages/Settings'
import WhitelistPage from './pages/Whitelist'

export default function App() {
  return (
    <div className="min-h-screen flex flex-col" data-theme="light">
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/details" element={<DetailsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/whitelist" element={<WhitelistPage />} />
      </Routes>
    </div>
  )
}
