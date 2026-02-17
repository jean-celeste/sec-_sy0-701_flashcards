import { useEffect, useMemo, useState } from 'react'
import type { Card } from '../data/cards'
import { CARDS } from '../data/cards'
import type { DomainFilter, StatusFilter } from '../constants/domains'

export type CardStatus = 'known' | 'review'

interface StoredState {
  statusMap: Record<string, CardStatus>
  domainFilter: DomainFilter
  statusFilter: StatusFilter
  isShuffled: boolean
  acronymFirst: boolean
}

export interface DeckStats {
  knownCount: number
  reviewCount: number
  unseenCount: number
  progressPercent: number
}

export interface TabCounts {
  known: number
  review: number
  unseen: number
}

export interface UseDeckResult {
  cards: Card[]
  currentCard: Card | null
  currentIndex: number
  workDeck: Card[]
  stats: DeckStats
  tabCounts: TabCounts
  baseDeck: Card[]
  statusMap: Record<string, CardStatus>
  currentStatus?: CardStatus
  domainFilter: DomainFilter
  statusFilter: StatusFilter
  isShuffled: boolean
  acronymFirst: boolean
  setDomainFilter: (value: DomainFilter) => void
  setStatusFilter: (value: StatusFilter) => void
  toggleShuffle: () => void
  toggleFlipMode: () => void
  markKnown: () => void
  markReview: () => void
  resetAll: () => void
  goNext: () => void
  goPrev: () => void
}

const STORAGE_KEY = 'secplus_sy0_701_status_v1'

const DEFAULT_STATE: StoredState = {
  statusMap: {},
  domainFilter: 'all',
  statusFilter: 'all',
  isShuffled: false,
  acronymFirst: true,
}

let cachedInitial: StoredState | null = null

function getInitialState(): StoredState {
  if (cachedInitial) return cachedInitial

  // During build/SSR just return defaults
  if (typeof window === 'undefined') {
    cachedInitial = DEFAULT_STATE
    return cachedInitial
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) {
      cachedInitial = DEFAULT_STATE
      return cachedInitial
    }
    const parsed = JSON.parse(raw) as Partial<StoredState>
    cachedInitial = {
      ...DEFAULT_STATE,
      ...parsed,
      statusMap: parsed.statusMap && typeof parsed.statusMap === 'object'
        ? parsed.statusMap
        : {},
    }
    return cachedInitial
  } catch {
    cachedInitial = DEFAULT_STATE
    return cachedInitial
  }
}

function shuffleInPlace<T>(arr: T[]): void {
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
}

export function useDeck(): UseDeckResult {
  const initial = getInitialState()

  const [statusMap, setStatusMap] = useState<Record<string, CardStatus>>(
    () => initial.statusMap,
  )
  const [domainFilter, setDomainFilterState] = useState<DomainFilter>(
    () => initial.domainFilter,
  )
  const [statusFilter, setStatusFilterState] = useState<StatusFilter>(
    () => initial.statusFilter,
  )
  const [isShuffled, setIsShuffled] = useState(() => initial.isShuffled)
  const [acronymFirst, setAcronymFirst] = useState(() => initial.acronymFirst)
  const [currentIndex, setCurrentIndex] = useState(0)

  // Persist to localStorage whenever key state changes
  useEffect(() => {
    const toStore: StoredState = {
      statusMap,
      domainFilter,
      statusFilter,
      isShuffled,
      acronymFirst,
    }
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore))
    } catch {
      // ignore quota/availability issues
    }
  }, [statusMap, domainFilter, statusFilter, isShuffled, acronymFirst])

  const baseDeck = useMemo(() => {
    let deck = CARDS
    if (domainFilter === 'freq') {
      deck = CARDS.filter((c) => c.frequent)
    } else if (domainFilter !== 'all') {
      deck = CARDS.filter((c) => c.domain === domainFilter)
    }
    const result = [...deck]
    if (isShuffled) {
      shuffleInPlace(result)
    }
    return result
  }, [domainFilter, isShuffled])

  const workDeck = useMemo(() => {
    let deck = baseDeck
    if (statusFilter === 'known') {
      deck = baseDeck.filter((c) => statusMap[c.id] === 'known')
    } else if (statusFilter === 'review') {
      deck = baseDeck.filter((c) => statusMap[c.id] === 'review')
    } else if (statusFilter === 'unseen') {
      deck = baseDeck.filter((c) => !statusMap[c.id])
    }
    return deck
  }, [baseDeck, statusFilter, statusMap])

  const tabCounts: TabCounts = useMemo(() => {
    const known = baseDeck.filter((c) => statusMap[c.id] === 'known').length
    const review = baseDeck.filter((c) => statusMap[c.id] === 'review').length
    const unseen = baseDeck.filter((c) => !statusMap[c.id]).length
    return { known, review, unseen }
  }, [baseDeck, statusMap])

  const stats: DeckStats = useMemo(() => {
    const values = Object.values(statusMap)
    const knownCount = values.filter((v) => v === 'known').length
    const reviewCount = values.filter((v) => v === 'review').length
    const unseenCount = CARDS.length - knownCount - reviewCount
    const progressPercent = Math.round((knownCount / CARDS.length) * 100)
    return { knownCount, reviewCount, unseenCount, progressPercent }
  }, [statusMap])

  // Clamp current index if deck shrinks
  useEffect(() => {
    if (workDeck.length === 0) {
      setCurrentIndex(0)
      return
    }
    setCurrentIndex((idx) => {
      if (idx < 0) return 0
      if (idx > workDeck.length - 1) return workDeck.length - 1
      return idx
    })
  }, [workDeck.length])

  const currentCard = workDeck.length > 0 ? workDeck[currentIndex] ?? null : null
  const currentStatus = currentCard ? statusMap[currentCard.id] : undefined

  const setDomainFilter = (value: DomainFilter) => {
    setDomainFilterState(value)
    setCurrentIndex(0)
  }

  const setStatusFilter = (value: StatusFilter) => {
    setStatusFilterState(value)
    setCurrentIndex(0)
  }

  const toggleShuffle = () => {
    setIsShuffled((prev) => !prev)
    setCurrentIndex(0)
  }

  const toggleFlipMode = () => {
    setAcronymFirst((prev) => !prev)
  }

  const mark = (value: CardStatus) => {
    if (!currentCard) return
    setStatusMap((prev) => ({
      ...prev,
      [currentCard.id]: value,
    }))
    // Move forward within current filter if possible
    setCurrentIndex((idx) => (idx < workDeck.length - 1 ? idx + 1 : idx))
  }

  const markKnown = () => mark('known')
  const markReview = () => mark('review')

  const resetAll = () => {
    setStatusMap({})
    setDomainFilterState('all')
    setStatusFilterState('all')
    setIsShuffled(false)
    setAcronymFirst(true)
    setCurrentIndex(0)
  }

  const goNext = () => {
    if (workDeck.length === 0) return
    setCurrentIndex((idx) => (idx < workDeck.length - 1 ? idx + 1 : idx))
  }

  const goPrev = () => {
    if (workDeck.length === 0) return
    setCurrentIndex((idx) => (idx > 0 ? idx - 1 : idx))
  }

  return {
    cards: CARDS,
    baseDeck,
    currentCard,
    currentIndex,
    workDeck,
    stats,
    tabCounts,
    domainFilter,
    statusFilter,
    isShuffled,
    acronymFirst,
    statusMap,
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
  }
}

