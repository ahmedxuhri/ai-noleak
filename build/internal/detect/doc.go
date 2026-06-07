// Package detect is the layered scan engine: Aho-Corasick exact-match against
// the value column, then gitleaks regex rules + entropy + context heuristics.
// See SPEC.md §4 hot path scan.
package detect
