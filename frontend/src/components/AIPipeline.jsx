import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import {
  Database, Brain, Crosshair, Cpu, FileText, CheckCircle2,
} from 'lucide-react'

const PIPELINE_STAGES = [
  { id: 'ingest',  label: 'CVE Input',      icon: Database,     color: '#6366f1' },
  { id: 'qdrant',  label: 'Qdrant Search',   icon: Crosshair,    color: '#22d3ee' },
  { id: 'attck',   label: 'ATT&CK Map',      icon: Crosshair,    color: '#a78bfa' },
  { id: 'llm',     label: 'GPT-4o Analysis', icon: Brain,        color: '#ec4899' },
  { id: 'output',  label: 'Brief Output',    icon: FileText,     color: '#34d399' },
]

const nodeVariants = {
  idle:      { scale: 1, borderColor: '#e2e5ee' },
  active:    { scale: 1.1, borderColor: '#6366f1', transition: { type: 'spring', stiffness: 300 } },
  completed: { scale: 1, borderColor: '#059669', transition: { type: 'spring', stiffness: 200 } },
}

const particleVariants = {
  hidden: { x: 0, opacity: 0, scale: 0 },
  visible: {
    x: [0, 48],
    opacity: [0, 1, 1, 0],
    scale: [0.5, 1, 1, 0.5],
    transition: { duration: 1, ease: 'easeInOut', repeat: Infinity, repeatDelay: 0.3 },
  },
}

/**
 * AIPipeline — Animated node diagram showing the RAG pipeline stages.
 *
 * Props:
 *   isRunning  – boolean, starts the animation sequence
 *   onComplete – callback when animation finishes
 *   stage      – optional: manually control active stage index (0–4)
 */
export default function AIPipeline({ isRunning = false, onComplete, stage: externalStage }) {
  const [activeStage, setActiveStage] = useState(-1)
  const [completedStages, setCompletedStages] = useState([])

  useEffect(() => {
    if (externalStage !== undefined) {
      setActiveStage(externalStage)
      setCompletedStages(Array.from({ length: externalStage }, (_, i) => i))
      return
    }

    if (!isRunning) {
      setActiveStage(-1)
      setCompletedStages([])
      return
    }

    let idx = 0
    setActiveStage(0)
    setCompletedStages([])

    const interval = setInterval(() => {
      idx++
      if (idx < PIPELINE_STAGES.length) {
        setCompletedStages((prev) => [...prev, idx - 1])
        setActiveStage(idx)
      } else {
        setCompletedStages((prev) => [...prev, idx - 1])
        setActiveStage(-1)
        clearInterval(interval)
        onComplete?.()
      }
    }, 1800)

    return () => clearInterval(interval)
  }, [isRunning, externalStage, onComplete])

  const getNodeState = (i) => {
    if (completedStages.includes(i)) return 'completed'
    if (i === activeStage) return 'active'
    return 'idle'
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2rem 1rem' }}>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        style={{ textAlign: 'center', marginBottom: '2rem' }}
      >
        <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
          {isRunning ? 'AI Pipeline Processing' : 'AI Analysis Pipeline'}
        </div>
        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
          {isRunning
            ? `Stage ${Math.min(activeStage + 1, PIPELINE_STAGES.length)} of ${PIPELINE_STAGES.length}`
            : 'RAG-powered vulnerability intelligence'
          }
        </div>
      </motion.div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap', gap: 0 }}>
        {PIPELINE_STAGES.map((s, i) => {
          const state = getNodeState(i)
          const Icon = s.icon
          const isActive = state === 'active'
          const isCompleted = state === 'completed'

          return (
            <div key={s.id} style={{ display: 'flex', alignItems: 'center' }}>
              {/* Node */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.6rem', minWidth: 90 }}>
                <motion.div
                  variants={nodeVariants}
                  animate={state}
                  style={{
                    width: 54,
                    height: 54,
                    borderRadius: 16,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '2px solid',
                    background: isCompleted
                      ? 'rgba(5,150,105,0.08)'
                      : isActive
                        ? 'rgba(99,102,241,0.08)'
                        : '#f0f2f7',
                    color: isCompleted ? '#059669' : isActive ? '#6366f1' : 'var(--text-muted)',
                    boxShadow: isActive
                      ? `0 0 20px ${s.color}40, 0 0 40px ${s.color}15`
                      : isCompleted
                        ? '0 0 12px rgba(5,150,105,0.15)'
                        : 'none',
                    position: 'relative',
                  }}
                >
                  {isCompleted ? <CheckCircle2 size={22} /> : <Icon size={20} />}

                  {/* Pulse ring for active node */}
                  {isActive && (
                    <motion.div
                      style={{
                        position: 'absolute',
                        inset: -6,
                        borderRadius: 20,
                        border: `2px solid ${s.color}`,
                        opacity: 0,
                      }}
                      animate={{
                        opacity: [0, 0.4, 0],
                        scale: [0.95, 1.15, 1.25],
                      }}
                      transition={{
                        duration: 1.5,
                        repeat: Infinity,
                        ease: 'easeOut',
                      }}
                    />
                  )}
                </motion.div>

                <motion.span
                  animate={{
                    color: isCompleted ? '#059669' : isActive ? '#6366f1' : '#8890a6',
                  }}
                  style={{
                    fontSize: '0.68rem',
                    fontWeight: 600,
                    textAlign: 'center',
                    maxWidth: 80,
                    lineHeight: 1.3,
                  }}
                >
                  {s.label}
                </motion.span>
              </div>

              {/* Connector (not after last node) */}
              {i < PIPELINE_STAGES.length - 1 && (
                <div style={{
                  width: 48,
                  height: 2,
                  background: isCompleted ? '#059669' : isActive ? s.color : '#e2e5ee',
                  position: 'relative',
                  marginBottom: '2rem',
                  marginLeft: 4,
                  marginRight: 4,
                  borderRadius: 2,
                  boxShadow: isCompleted
                    ? '0 0 6px rgba(5,150,105,0.2)'
                    : isActive
                      ? `0 0 8px ${s.color}40`
                      : 'none',
                  transition: 'all 0.5s ease',
                }}>
                  {/* Data flow particle */}
                  {isActive && (
                    <motion.div
                      variants={particleVariants}
                      initial="hidden"
                      animate="visible"
                      style={{
                        position: 'absolute',
                        top: -3,
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: '#6366f1',
                        boxShadow: '0 0 8px rgba(99,102,241,0.4)',
                      }}
                    />
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Processing label below */}
      {isRunning && activeStage >= 0 && activeStage < PIPELINE_STAGES.length && (
        <motion.div
          key={activeStage}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          style={{
            marginTop: '1.5rem',
            padding: '0.5rem 1rem',
            background: 'rgba(99,102,241,0.06)',
            border: '1px solid rgba(99,102,241,0.15)',
            borderRadius: 'var(--radius)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          >
            <Cpu size={14} style={{ color: '#6366f1' }} />
          </motion.div>
          <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#6366f1' }}>
            {PIPELINE_STAGES[activeStage].label}…
          </span>
        </motion.div>
      )}

      {/* All complete */}
      {completedStages.length === PIPELINE_STAGES.length && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ type: 'spring', stiffness: 300 }}
          style={{
            marginTop: '1.5rem',
            padding: '0.5rem 1rem',
            background: 'rgba(5,150,105,0.08)',
            border: '1px solid rgba(5,150,105,0.15)',
            borderRadius: 'var(--radius)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <CheckCircle2 size={14} style={{ color: '#059669' }} />
          <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#059669' }}>
            Analysis Complete
          </span>
        </motion.div>
      )}
    </div>
  )
}
