package netcheck

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	_ "errors"
	"fmt"
	"github.com/araddon/dateparse"
	"io"
	"net"
	"os"
	"regexp"
	_ "sort"
	"strings"
	"sync"
	"time"
)

// fingerprint represents the unique hash of a probe response and metadata, including its version and timestamp.
type fingerprint struct {
	Hash    string    `json:"hash"`
	Version int       `json:"version"`
	Added   time.Time `json:"added"`
}

// fingerprintCandidate represents a new, untrusted fingerprint observed over time.
type fingerprintCandidate struct {
	Hash      string    `json:"hash"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// ProbeTarget represents a network endpoint and related metadata for performing probe operations.
type ProbeTarget struct {
	Name                string          `json:"name"`
	Host                string          `json:"host"`
	Port                int             `json:"port"`
	Probe               string          `json:"probe,omitempty"`
	ReadLimit           int             `json:"read_limit"`
	EncodedFingerprints fingerprintBlob `json:"fingerprint_data"`
	EncodedCandidates   candidateBlob   `json:"candidate_data"`

	KnownFingerprints     []fingerprint          `json:"-"`
	CandidateFingerprints []fingerprintCandidate `json:"-"`
}

// ConsensusResult represents the outcome of a consensus evaluation for a probe target, including match status and votes.
type ConsensusResult struct {
	Target  ProbeTarget
	Matched bool
	Actual  string
	Matches int
	Votes   map[string]int
	Error   error
}

const FingerprintExpiry = 90 * 24 * time.Hour // FingerprintExpiry defines the duration after which a fingerprint is considered expired.

// LoadProbes reads a JSON file from the given path and unmarshals its content into a slice of ProbeTarget structs.
// It returns the slice of ProbeTarget and an error if the file reading or unmarshalling fails.
func LoadProbes(path string) ([]ProbeTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var probes []ProbeTarget
	if err := json.Unmarshal(data, &probes); err != nil {
		return nil, err
	}
	for i := range probes {
		probes[i].KnownFingerprints = probes[i].EncodedFingerprints.Extract()
	}
	return probes, nil
}

// saveProbes saves a slice of ProbeTarget objects to a JSON file at the specified path.
// Returns an error if marshalling or writing to the file fails.
func saveProbes(path string, targets []ProbeTarget) error {
	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// probeTCP establishes a TCP connection to a target, sends a probe string, reads a response, and returns its SHA-256 hash.
func probeTCP(target ProbeTarget) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port)))
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			return
		}
	}(conn)

	if target.Probe != "" {
		err := conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if err != nil {
			return "", err
		}
		if _, err := conn.Write([]byte(target.Probe)); err != nil {
			return "", fmt.Errorf("write: %w", err)
		}
	}

	err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return "", err
	}
	buf := make([]byte, target.ReadLimit)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read: %w", err)
	}

	content := string(buf[:n])
	cleaned := scrubDateStrings(content)
	fmt.Printf("\nProbe \"%s\" response:\n%s\n", target.Name, cleaned)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(cleaned)))
	return hash, nil
}

// CheckConsensus evaluates consensus on probe results for a set of targets using a vote-based threshold and returns results.
func CheckConsensus(targets []ProbeTarget) []ConsensusResult {
	var wg sync.WaitGroup
	results := make([]ConsensusResult, len(targets))

	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			actual, err := probeTCP(target)
			votes := map[string]int{}
			for _, fp := range target.KnownFingerprints {
				votes[fp.Hash]++
			}
			match := false
			if err == nil {
				votes[actual]++
				if containsHash(target.KnownFingerprints, actual) {
					match = true
				} else if handleFingerprintCandidates(&target, actual) {
					match = true
				}
			}
			results[i] = ConsensusResult{
				Target:  target,
				Matched: match,
				Actual:  actual,
				Matches: votes[actual],
				Votes:   votes,
				Error:   err,
			}
		}()
	}
	wg.Wait()
	return results
}

// promoteIfTrusted determines if a fingerprint candidate should be promoted as trusted based on occurrence and duration.
func promoteIfTrusted(candidate fingerprintCandidate) bool {
	age := time.Since(candidate.FirstSeen)
	return candidate.Count >= 5 && age >= 48*time.Hour
}

// containsHash checks if the target hash exists in the list of Fingerprints and is within the allowed expiry duration.
func containsHash(list []fingerprint, hash string) bool {
	hash = strings.ToLower(hash)
	now := time.Now().UTC()
	for _, s := range list {
		if strings.ToLower(s.Hash) == hash && now.Sub(s.Added) <= FingerprintExpiry {
			return true
		}
	}
	return false
}

// handleFingerprintCandidates processes and manages fingerprint candidates for a target, updating them based on activity.
func handleFingerprintCandidates(target *ProbeTarget, hash string) bool {
	hash = strings.ToLower(hash)
	now := time.Now().UTC()
	isNew := true

	// Use index-based loop to allow removal
	list := &target.CandidateFingerprints
	for i := 0; i < len(*list); i++ {
		candidate := &(*list)[i]
		candidateHash := strings.ToLower(candidate.Hash)

		// Update the active candidate hash.
		if candidateHash == hash && now.Sub(candidate.FirstSeen) <= FingerprintExpiry {
			candidate.LastSeen = now
			candidate.Count++
			return true
		}

		// Remove an expired candidate.
		if now.Sub(candidate.FirstSeen) > FingerprintExpiry {
			// Remove the expired candidate from the list
			*list = append((*list)[:i], (*list)[i+1:]...)
			// Adjust the index since the slice is now shorter
			i--
			isNew = false
		}

		// Add to known fingerprints.
		if promoteIfTrusted(*candidate) {
			target.KnownFingerprints = append(target.KnownFingerprints, fingerprint{
				Hash:    candidate.Hash,
				Version: candidate.Count,
				Added:   candidate.FirstSeen,
			})
			return true
		}
	}

	if isNew {
		// Add a new candidate.
		*list = append(*list, fingerprintCandidate{
			Hash:      hash,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		})
		return true
	}

	return false
}

// GetConsensusVerdict determines if the number of matching results meets or exceeds the required majority threshold.
func GetConsensusVerdict(results []ConsensusResult, requiredMajority int) bool {
	total := 0
	matching := 0
	for _, res := range results {
		total++
		if res.Matched {
			matching++
		}
	}
	return matching >= requiredMajority
}

// PrintSummary prints a summary of consensus results, including status, target details, actual result, and potential errors.
func PrintSummary(results []ConsensusResult) {
	for _, res := range results {
		status := "FAIL"
		if res.Matched {
			status = "PASS"
		}

		fmt.Printf("[%s] \"%s\" %s:%d → %s\n", status, res.Target.Name, res.Target.Host, res.Target.Port, res.Actual)
		if res.Error != nil {
			fmt.Printf("  Error: %v\n", res.Error)
		}
	}
}

// LearnFingerprints updates known fingerprints if they are missing and probes succeed.
func LearnFingerprints(path string, targets []ProbeTarget) error {
	updated := false
	cutoff := time.Now().UTC().Add(-FingerprintExpiry)
	for i := range targets {
		// Remove expired fingerprints
		var cleaned []fingerprint
		for _, fp := range targets[i].KnownFingerprints {
			if fp.Added.After(cutoff) {
				cleaned = append(cleaned, fp)
			}
		}
		targets[i].KnownFingerprints = cleaned

		if len(cleaned) == 0 {
			hash, err := probeTCP(targets[i])
			if err != nil {
				fmt.Printf("Learning failed for %s:%d → %v\n", targets[i].Host, targets[i].Port, err)
				continue
			}
			targets[i].KnownFingerprints = append(targets[i].KnownFingerprints, fingerprint{
				Hash:    hash,
				Version: 1,
				Added:   time.Now().UTC(),
			})
			targets[i].EncodedFingerprints = wrap(targets[i].KnownFingerprints)
			targets[i].EncodedCandidates = wrapCandidates(targets[i].CandidateFingerprints)
			fmt.Printf("Learned fingerprint for %s:%d → %s\n", targets[i].Host, targets[i].Port, hash)
			updated = true
		}
	}
	if updated {
		return saveProbes(path, targets)
	}
	return nil
}

// scrubPatterns contains regular expressions to detect various date and time formats within a given string.
// A pattern may be a bit broad. It is better to remove a "false" date than to leave one in. These are candidate
// patterns that `dateparse` will confirm.
var scrubPatterns = []*regexp.Regexp{
	// RFC 1123
	regexp.MustCompile(`(?i)(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT`),
	// ISO8601
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:?\d{2})?`),
	// US-style: 04/09/2024 01:23:45 or 09-04-2024
	regexp.MustCompile(`\d{1,2}[/-]\d{1,2}[/-]\d{2,4}( \d{1,2}:\d{2}(:\d{2})?( ?[APap][Mm])?)?`),
	// Time strings
	regexp.MustCompile(`\b\d{1,2}:\d{2}(:\d{2})?( ?[APap][Mm])?\b`),
	// Compact date - 8 numbers in a row: YYYYMMDD, MMDDYYYY, DDMMYYYY, etc.
	regexp.MustCompile(`\b\d{8}\b`),
}

func scrubDateStrings(input string) string {
	cleaned := input
	seen := make(map[string]struct{})

	for _, pattern := range scrubPatterns {
		matches := pattern.FindAllString(cleaned, -1)
		for _, match := range matches {
			if _, exists := seen[match]; exists {
				continue
			}
			if _, err := dateparse.ParseAny(match); err == nil {
				cleaned = strings.ReplaceAll(cleaned, match, "")
				seen[match] = struct{}{}
			}
		}
	}
	return cleaned
}
