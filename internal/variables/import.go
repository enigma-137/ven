package variables

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/envfile"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/vault"
)

// ImportMode controls how existing variables are treated.
type ImportMode string

const (
	// ModeMerge adds and updates variables, leaving others untouched (default).
	ModeMerge ImportMode = "merge"
	// ModeReplace makes the environment match the file exactly, removing
	// variables that are not in the file.
	ModeReplace ImportMode = "replace"
)

// ParseMode validates a mode string; "" means merge.
func ParseMode(s string) (ImportMode, error) {
	switch s {
	case "", string(ModeMerge):
		return ModeMerge, nil
	case string(ModeReplace):
		return ModeReplace, nil
	}
	return "", domain.Invalid("mode", "must be %q or %q", ModeMerge, ModeReplace)
}

// ChangeStatus classifies one key in an import plan.
type ChangeStatus string

const (
	StatusNew       ChangeStatus = "new"
	StatusChanged   ChangeStatus = "changed" // conflict: existing key with a different value
	StatusUnchanged ChangeStatus = "unchanged"
	StatusRemoved   ChangeStatus = "removed" // replace mode only
)

// Resolution decides what happens to a conflicting key.
type Resolution string

const (
	Overwrite Resolution = "overwrite"
	Keep      Resolution = "keep"
)

// PlanItem describes one key. It never contains values.
type PlanItem struct {
	Key          string       `json:"key"`
	Status       ChangeStatus `json:"status"`
	Line         int          `json:"line,omitempty"`
	Type         string       `json:"type"`
	TypeReason   string       `json:"typeReason,omitempty"`
	ExistingType string       `json:"existingType,omitempty"`
}

// PlanCounts summarizes a plan.
type PlanCounts struct {
	New       int `json:"new"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	Removed   int `json:"removed"`
}

// ImportPlan is a preview of an import.
type ImportPlan struct {
	Mode   ImportMode `json:"mode"`
	Items  []PlanItem `json:"items"`
	Counts PlanCounts `json:"counts"`
}

// Conflicts returns the keys whose values differ from stored values.
func (p *ImportPlan) Conflicts() []string {
	var out []string
	for _, it := range p.Items {
		if it.Status == StatusChanged {
			out = append(out, it.Key)
		}
	}
	return out
}

// ImportOptions control ApplyImport.
type ImportOptions struct {
	Mode ImportMode
	// OnConflict is the default resolution for changed keys. Empty means
	// conflicts must each be resolved in Resolutions.
	OnConflict  Resolution
	Resolutions map[string]Resolution
	// Types overrides the display type for new keys (and changed keys if set).
	Types map[string]string
	// ConfirmReplace must be true for replace mode.
	ConfirmReplace bool
}

// ImportResult reports what ApplyImport changed.
type ImportResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Kept      int `json:"kept"`
	Unchanged int `json:"unchanged"`
	Removed   int `json:"removed"`
}

var (
	// ErrReplaceNotConfirmed guards replace mode.
	ErrReplaceNotConfirmed = errors.New("replace mode removes variables that are not in the file; explicit confirmation is required")
	// ErrUnresolvedConflicts means a changed key has no resolution.
	ErrUnresolvedConflicts = errors.New("import has conflicting values that need a keep or overwrite decision")
)

// applyHook lets tests inject a failure after step i of an import commit.
var applyHook func(step int) error

// ValidateEntries rejects entries that could not have come from a clean parse.
func ValidateEntries(entries []envfile.Entry) error {
	seen := map[string]bool{}
	for _, e := range entries {
		if err := ValidateKey(e.Key); err != nil {
			return err
		}
		if err := ValidateValue(e.Value); err != nil {
			return fmt.Errorf("%s: %w", e.Key, err)
		}
		if seen[e.Key] {
			return domain.Invalid("key", "duplicate key %s", e.Key)
		}
		seen[e.Key] = true
	}
	return nil
}

func plan(ctx context.Context, q storage.Querier, k *vault.Key, envID string, entries []envfile.Entry, mode ImportMode) (*ImportPlan, map[string]storage.Variable, error) {
	existing := map[string]storage.Variable{}
	var projectID string
	if envID != "" {
		e, err := projectOf(ctx, q, envID)
		if err != nil {
			return nil, nil, err
		}
		projectID = e.ProjectID
		rows, err := storage.ListVariables(ctx, q, envID, "")
		if err != nil {
			return nil, nil, err
		}
		for _, r := range rows {
			existing[r.Key] = r
		}
	}
	p := &ImportPlan{Mode: mode, Items: []PlanItem{}}
	inFile := map[string]bool{}
	for _, e := range entries {
		inFile[e.Key] = true
		r, ok := existing[e.Key]
		if !ok {
			typ, reason := Classify(e.Key)
			p.Items = append(p.Items, PlanItem{Key: e.Key, Status: StatusNew, Line: e.Line, Type: typ, TypeReason: reason})
			p.Counts.New++
			continue
		}
		cur, err := decrypt(k, projectID, r)
		if err != nil {
			return nil, nil, err
		}
		item := PlanItem{Key: e.Key, Line: e.Line, Type: r.DisplayType, ExistingType: r.DisplayType}
		if cur == e.Value {
			item.Status = StatusUnchanged
			p.Counts.Unchanged++
		} else {
			item.Status = StatusChanged
			p.Counts.Changed++
		}
		p.Items = append(p.Items, item)
	}
	if mode == ModeReplace {
		var removed []string
		for key := range existing {
			if !inFile[key] {
				removed = append(removed, key)
			}
		}
		sort.Strings(removed)
		for _, key := range removed {
			p.Items = append(p.Items, PlanItem{Key: key, Status: StatusRemoved, Type: existing[key].DisplayType, ExistingType: existing[key].DisplayType})
			p.Counts.Removed++
		}
	}
	return p, existing, nil
}

// PlanImport previews importing entries into envID without changing
// anything. envID may be empty for an environment that does not exist yet.
// Decrypted existing values are compared in memory and never returned.
func (s *Service) PlanImport(ctx context.Context, k *vault.Key, envID string, entries []envfile.Entry, mode ImportMode) (*ImportPlan, error) {
	if err := ValidateEntries(entries); err != nil {
		return nil, err
	}
	p, _, err := plan(ctx, s.db, k, envID, entries, mode)
	return p, err
}

// ApplyImport commits an import in a single transaction. The plan is
// recomputed inside the transaction so concurrent edits are not lost
// silently; any error rolls back every change.
func (s *Service) ApplyImport(ctx context.Context, k *vault.Key, envID string, entries []envfile.Entry, opts ImportOptions) (*ImportResult, error) {
	if err := ValidateEntries(entries); err != nil {
		return nil, err
	}
	mode, err := ParseMode(string(opts.Mode))
	if err != nil {
		return nil, err
	}
	if mode == ModeReplace && !opts.ConfirmReplace {
		return nil, ErrReplaceNotConfirmed
	}
	for key, t := range opts.Types {
		if !ValidType(t) {
			return nil, domain.Invalid("type", "%s: must be %q or %q", key, TypeSecret, TypeText)
		}
	}
	res := &ImportResult{}
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		e, err := projectOf(ctx, tx, envID)
		if err != nil {
			return err
		}
		p, existing, err := plan(ctx, tx, k, envID, entries, mode)
		if err != nil {
			return err
		}
		values := map[string]string{}
		for _, en := range entries {
			values[en.Key] = en.Value
		}
		now := storage.Now()
		order, err := storage.NextVariableOrder(ctx, tx, envID)
		if err != nil {
			return err
		}
		for step, it := range p.Items {
			if applyHook != nil {
				if err := applyHook(step); err != nil {
					return err
				}
			}
			switch it.Status {
			case StatusNew:
				typ := it.Type
				if t, ok := opts.Types[it.Key]; ok {
					typ = t
				}
				r := storage.Variable{ID: storage.NewID(), EnvironmentID: envID, Key: it.Key, DisplayType: typ,
					SortOrder: order, CreatedAt: now, UpdatedAt: now}
				order++
				if err := encrypt(k, e.ProjectID, &r, values[it.Key]); err != nil {
					return err
				}
				if err := storage.InsertVariable(ctx, tx, &r); err != nil {
					return err
				}
				res.Created++
			case StatusChanged:
				resolution, ok := opts.Resolutions[it.Key]
				if !ok {
					resolution = opts.OnConflict
				}
				switch resolution {
				case Keep:
					res.Kept++
					continue
				case Overwrite:
				default:
					return fmt.Errorf("%w: %s", ErrUnresolvedConflicts, it.Key)
				}
				r := existing[it.Key]
				if t, ok := opts.Types[it.Key]; ok {
					r.DisplayType = t
				}
				r.UpdatedAt = now
				if err := encrypt(k, e.ProjectID, &r, values[it.Key]); err != nil {
					return err
				}
				if err := storage.UpdateVariable(ctx, tx, &r); err != nil {
					return err
				}
				res.Updated++
			case StatusUnchanged:
				res.Unchanged++
			case StatusRemoved:
				if err := storage.DeleteVariable(ctx, tx, existing[it.Key].ID); err != nil {
					return err
				}
				res.Removed++
			}
		}
		if res.Created+res.Updated+res.Removed > 0 {
			return storage.TouchEnvironment(ctx, tx, envID, now)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
