import type { Domain } from '../data/cards'

export type DomainFilter = 'all' | 'freq' | Domain
export type StatusFilter = 'all' | 'known' | 'review' | 'unseen'

export const DOMAIN_COLORS: Record<DomainFilter, string> = {
  '1': '#60a5fa',
  '2': '#f97316',
  '3': '#22d3ee',
  '4': '#facc15',
  '5': '#4ade80',
  freq: '#ff4d6d',
  all: '#a78bfa',
}

export const DOMAIN_LABELS: Record<Domain, string> = {
  '1': 'D1 · General Security Concepts (12%)',
  '2': 'D2 · Threats, Vulnerabilities & Mitigations (22%)',
  '3': 'D3 · Security Architecture (18%)',
  '4': 'D4 · Security Operations (28%)',
  '5': 'D5 · Security Program Management & Oversight (20%)',
}

export const DOMAIN_PILL_LABELS: Record<Domain, string> = {
  '1': 'D1 · General',
  '2': 'D2 · Threats',
  '3': 'D3 · Arch',
  '4': 'D4 · Ops',
  '5': 'D5 · Gov',
}

export const DOMAIN_NAV_LABELS: Record<DomainFilter, string> = {
  all: 'All',
  freq: '⚡ Frequently Tested',
  '1': 'D1 · General Security',
  '2': 'D2 · Threats & Vulns',
  '3': 'D3 · Architecture',
  '4': 'D4 · Operations',
  '5': 'D5 · Governance',
}

