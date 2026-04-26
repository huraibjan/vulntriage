import { NavLink } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard,
  ShieldAlert,
  Brain,
  ShieldCheck,
} from 'lucide-react'

const sidebarVariants = {
  hidden: { x: -20, opacity: 0 },
  visible: {
    x: 0, opacity: 1,
    transition: { duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94], staggerChildren: 0.08, delayChildren: 0.2 },
  },
}

const itemVariants = {
  hidden: { x: -12, opacity: 0 },
  visible: { x: 0, opacity: 1, transition: { duration: 0.35 } },
}

const NAV_LINKS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/vulnerabilities', icon: ShieldAlert, label: 'Vulnerabilities' },
]

export default function Sidebar() {
  return (
    <motion.aside
      className="sidebar"
      variants={sidebarVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Brand */}
      <motion.div className="sidebar-brand" variants={itemVariants}>
        <motion.div
          className="sidebar-brand-icon"
          whileHover={{ scale: 1.08, rotate: 5 }}
          whileTap={{ scale: 0.95 }}
          transition={{ type: 'spring', stiffness: 400 }}
        >
          <ShieldCheck size={20} />
        </motion.div>
        <div className="sidebar-brand-text">
          <h1>VulnTriage</h1>
          <span>AI Vulnerability Intelligence</span>
        </div>
      </motion.div>

      {/* Navigation */}
      <motion.div className="sidebar-section-label" variants={itemVariants}>
        Navigation
      </motion.div>
      <nav className="sidebar-nav">
        {NAV_LINKS.map((link) => {
          const Icon = link.icon
          return (
            <motion.div key={link.to} variants={itemVariants}>
              <NavLink
                to={link.to}
                end={link.end}
                className={({ isActive }) => isActive ? 'active' : ''}
              >
                <motion.span
                  style={{ display: 'flex' }}
                  whileHover={{ scale: 1.12, rotate: -3 }}
                  transition={{ type: 'spring', stiffness: 400 }}
                >
                  <Icon size={18} />
                </motion.span>
                {link.label}
              </NavLink>
            </motion.div>
          )
        })}
      </nav>

      {/* Footer */}
      <motion.div className="sidebar-footer" variants={itemVariants}>
        <motion.div
          className="sidebar-footer-badge"
          animate={{
            boxShadow: [
              '0 0 4px rgba(5,150,105,0.06)',
              '0 0 10px rgba(5,150,105,0.12)',
              '0 0 4px rgba(5,150,105,0.06)',
            ],
          }}
          transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
        >
          <Brain size={11} />
          GPT-4o-mini Active
        </motion.div>
        <div>VulnTriage v2.0 · MSU Thesis Project</div>
        <div style={{ marginTop: '0.15rem' }}>Huraib Jan Sarhandi</div>
      </motion.div>
    </motion.aside>
  )
}
