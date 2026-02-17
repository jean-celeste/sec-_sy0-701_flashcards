import { useCallback, useEffect, useMemo, useState } from 'react'
import { useDeck } from './hooks/useDeck'
import type { DomainFilter } from './constants/domains'
import {
  DOMAIN_COLORS,
  DOMAIN_LABELS,
  DOMAIN_NAV_LABELS,
  DOMAIN_PILL_LABELS,
} from './constants/domains'
import './index.css'

function App() {
  const {
    cards,
    currentCard,
    currentIndex,
    workDeck,
    stats,
    tabCounts,
    domainFilter,
    statusFilter,
    isShuffled,
    acronymFirst,
    currentStatus,
    setDomainFilter,
    setStatusFilter,
    toggleShuffle,
    toggleFlipMode,
    markKnown,
    markReview,
    resetAll,
    goNext,
    goPrev,
  } = useDeck()

  const [isFlipped, setIsFlipped] = useState(false)
  const [navDirection, setNavDirection] = useState<'next' | 'prev' | null>(null)

  const hasCards = workDeck.length > 0 && currentCard

  useEffect(() => {
    setIsFlipped(false)
  }, [currentCard])

  const handleFlip = useCallback(() => {
    if (!currentCard) return
    setIsFlipped((prev) => !prev)
  }, [currentCard])

  const handleNext = useCallback(() => {
    if (!hasCards || currentIndex === workDeck.length - 1) return
    setNavDirection('next')
    goNext()
  }, [goNext, hasCards, currentIndex, workDeck.length])

  const handlePrev = useCallback(() => {
    if (!hasCards || currentIndex === 0) return
    setNavDirection('prev')
    goPrev()
  }, [goPrev, hasCards, currentIndex])

  const handleMarkKnown = useCallback(() => {
    if (!hasCards) return
    setNavDirection('next')
    markKnown()
  }, [hasCards, markKnown])

  const handleMarkReview = useCallback(() => {
    if (!hasCards) return
    setNavDirection('next')
    markReview()
  }, [hasCards, markReview])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)
      ) {
        return
      }

      if (e.code === 'Space') {
        e.preventDefault()
        handleFlip()
      } else if (e.code === 'ArrowRight') {
        handleNext()
      } else if (e.code === 'ArrowLeft') {
        handlePrev()
      } else if (e.key === 'k' || e.key === 'K') {
        handleMarkKnown()
      } else if (e.key === 'r' || e.key === 'R') {
        handleMarkReview()
      }
    }

    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [handleNext, handlePrev, handleFlip, handleMarkKnown, handleMarkReview])

  const domainButtons = useMemo(() => {
    const filters: DomainFilter[] = ['all', 'freq', '1', '2', '3', '4', '5']
    return filters.map((d) => {
      let count: number
      if (d === 'all') {
        count = cards.length
      } else if (d === 'freq') {
        count = cards.filter((c) => c.frequent).length
      } else {
        count = cards.filter((c) => c.domain === d).length
      }
      return { id: d, count, label: DOMAIN_NAV_LABELS[d] }
    })
  }, [cards])

  const sceneOutline = useMemo(() => {
    if (currentStatus === 'known') {
      return '2px solid rgba(0,229,160,0.5)'
    }
    if (currentStatus === 'review') {
      return '2px solid rgba(255,159,67,0.5)'
    }
    return 'none'
  }, [currentStatus])

  const domainColor =
    currentCard?.domain && DOMAIN_COLORS[currentCard.domain]
      ? DOMAIN_COLORS[currentCard.domain]
      : DOMAIN_COLORS.all

  const pillLabel =
    currentCard?.domain && DOMAIN_PILL_LABELS[currentCard.domain]
      ? DOMAIN_PILL_LABELS[currentCard.domain]
      : ''

  const showComplete =
    stats.knownCount > 0 && stats.knownCount === cards.length

  return (
    <>
      <header>
        <div className="badge">STUDY TOOL · V2</div>
        <h1>
          CompTIA <span>Security+</span> SY0-701
        </h1>
        <div className="subtitle">
          330 Acronym Flashcards · Organized by Domain · Research-backed
          Frequency Tags
        </div>
      </header>

      {/* Stats */}
      <div className="stats z1">
        <div className="stat">
          <div className="stat-num" style={{ color: 'var(--accent)' }}>
            {workDeck.length}
          </div>
          <div className="stat-label">In Deck</div>
        </div>
        <div className="stat">
          <div className="stat-num" style={{ color: 'var(--known)' }}>
            {stats.knownCount}
          </div>
          <div className="stat-label">Known</div>
        </div>
        <div className="stat">
          <div className="stat-num" style={{ color: 'var(--review)' }}>
            {stats.reviewCount}
          </div>
          <div className="stat-label">Review</div>
        </div>
        <div className="stat">
          <div className="stat-num" style={{ color: 'var(--muted)' }}>
            {stats.unseenCount}
          </div>
          <div className="stat-label">Unseen</div>
        </div>
      </div>

      {/* Progress */}
      <div className="progress-wrap">
        <div
          className="progress-bar"
          style={{ width: `${stats.progressPercent}%` }}
        />
      </div>

      {/* Domain selector */}
      <div className="domain-nav">
        {domainButtons.map((btn) => (
          <button
            key={btn.id}
            type="button"
            className={`domain-btn ${
              domainFilter === btn.id ? 'active' : ''
            }`}
            onClick={() => setDomainFilter(btn.id)}
            data-d={btn.id}
          >
            <span className="dot" />
            {btn.label} ({btn.count})
          </button>
        ))}
      </div>

      {/* Controls */}
      <div className="controls">
        <button
          type="button"
          className={`btn ${isShuffled ? 'active' : ''}`}
          onClick={toggleShuffle}
        >
          {isShuffled ? '⇄ Shuffled' : '⇄ Shuffle'}
        </button>
        <button
          type="button"
          className="btn"
          onClick={toggleFlipMode}
        >
          {acronymFirst
            ? '⇌ Acronym → Definition'
            : '⇌ Definition → Acronym'}
        </button>
        <button
          type="button"
          className="btn danger"
          onClick={() => {
            resetAll()
            setIsFlipped(false)
          }}
        >
          ↺ Reset All
        </button>
      </div>

      {/* Status filter */}
      <div className="filter-tabs">
        <button
          type="button"
          className={`tab ${statusFilter === 'all' ? 'active' : ''}`}
          onClick={() => setStatusFilter('all')}
        >
          All
        </button>
        <button
          type="button"
          className={`tab ${statusFilter === 'unseen' ? 'active' : ''}`}
          onClick={() => setStatusFilter('unseen')}
          id="tab-unseen"
        >
          Unseen ({tabCounts.unseen})
        </button>
        <button
          type="button"
          className={`tab ${statusFilter === 'review' ? 'active' : ''}`}
          onClick={() => setStatusFilter('review')}
          id="tab-review"
        >
          Needs Review ({tabCounts.review})
        </button>
        <button
          type="button"
          className={`tab ${statusFilter === 'known' ? 'active' : ''}`}
          onClick={() => setStatusFilter('known')}
          id="tab-known"
        >
          Known ({tabCounts.known})
        </button>
      </div>

      {/* Counter */}
      <div className="card-counter z1" id="cardCounter">
        {hasCards
          ? `Card ${currentIndex + 1} of ${workDeck.length}`
          : 'No cards match this filter'}
      </div>

      {/* Flashcard */}
      <div
        className="scene"
        id="scene"
        style={{ outline: sceneOutline, borderRadius: '14px' }}
        onClick={handleFlip}
      >
        <div
          key={currentCard?.id ?? 'empty'}
          className={`card-wrapper ${
            navDirection === 'next'
              ? 'slide-next'
              : navDirection === 'prev'
                ? 'slide-prev'
                : ''
          }`}
        >
          <div
            className={`card ${isFlipped ? 'flipped' : ''}`}
            id="card"
          >
          <div className="card-face card-front" id="frontFace">
            <div
              className="card-stripe"
              id="frontStripe"
              style={{
                background: `linear-gradient(90deg,${domainColor}88,${domainColor})`,
              }}
            />
            <div className="card-hint">Click to flip</div>
            <div
              className="card-domain-pill"
              id="frontPill"
              style={{
                color: domainColor,
                borderColor: `${domainColor}55`,
                background: `${domainColor}11`,
              }}
            >
              {pillLabel}
            </div>
            {currentCard?.frequent && (
              <div className="freq-badge">⚡ Frequently Tested</div>
            )}
            <div className="card-acronym" id="frontText">
              {hasCards
                ? acronymFirst
                  ? currentCard?.acronym
                  : currentCard?.definition
                : '—'}
            </div>
            <div className="card-sub">
              {acronymFirst
                ? 'tap to reveal definition'
                : 'tap to reveal acronym'}
            </div>
          </div>
          <div className="card-face card-back" id="backFace">
            <div
              className="card-stripe"
              id="backStripe"
              style={{
                background: `linear-gradient(90deg,${domainColor},${domainColor}77)`,
              }}
            />
            <div className="card-hint">Click to flip back</div>
            <div
              className="card-domain-pill"
              id="backPill"
              style={{
                color: domainColor,
                borderColor: `${domainColor}55`,
                background: `${domainColor}11`,
              }}
            >
              {pillLabel}
            </div>
            <div className="card-full" id="backText">
              {hasCards
                ? acronymFirst
                  ? currentCard?.definition
                  : currentCard?.acronym
                : 'No cards'}
            </div>
            <div className="card-full-sub" id="backSub">
              {hasCards
                ? acronymFirst
                  ? currentCard?.acronym
                  : (() => {
                      const text = currentCard?.definition ?? ''
                      return text.length > 36
                        ? `${text.substring(0, 36)}…`
                        : text
                    })()
                : ''}
          </div>
        </div>
          </div>
        </div>
      </div>

      {/* Mark buttons */}
      <div className="card-actions">
        <button
          type="button"
          className="action-btn btn-known"
          onClick={handleMarkKnown}
        >
          ✓ Known
        </button>
        <button
          type="button"
          className="action-btn btn-review"
          onClick={handleMarkReview}
        >
          ⚑ Needs Review
        </button>
      </div>

      {/* Navigation */}
      <div className="nav">
        <button
          type="button"
          className="nav-btn"
          id="prevBtn"
          onClick={handlePrev}
          disabled={!hasCards || currentIndex === 0}
        >
          ←
        </button>
        <button
          type="button"
          className="nav-btn"
          onClick={handleFlip}
          title="Flip"
        >
          ↕
        </button>
        <button
          type="button"
          className="nav-btn"
          id="nextBtn"
          onClick={handleNext}
          disabled={!hasCards || currentIndex === workDeck.length - 1}
        >
          →
        </button>
      </div>

      <div className="keyboard-hint z1">
        <kbd>Space</kbd> Flip &nbsp;|&nbsp; <kbd>←</kbd>
        <kbd>→</kbd> Navigate &nbsp;|&nbsp; <kbd>K</kbd> Known &nbsp;|&nbsp;{' '}
        <kbd>R</kbd> Review
      </div>

      {showComplete && (
        <div id="completeMsg" className="complete-msg">
          🎉 All {cards.length} acronyms marked as known — you&apos;re
          exam-ready!
        </div>
      )}

      {/* Legend */}
      <div className="legend">
        <div className="legend-title">Domain Key</div>
        <div className="legend-item">
          <div
            className="legend-dot"
            style={{ background: 'var(--dfreq)' }}
          />
          ⚡ Frequently Tested (research-based)
        </div>
        {(['1', '2', '3', '4', '5'] as const).map((d) => (
          <div key={d} className="legend-item">
            <div
              className="legend-dot"
              style={{ background: DOMAIN_COLORS[d] }}
            />
            {DOMAIN_LABELS[d]}
          </div>
        ))}
      </div>
    </>
  )
}

export default App
