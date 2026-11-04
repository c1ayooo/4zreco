package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Project is a row in the projects table (schema §D2). Projects are the
// attribution axis for tasks and conversations; project_scope is an
// organizational definition only — this build has no asset fence/authz.
type Project struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status"` // active | archived
	TaskCount   int64          `json:"task_count"`
	ConvCount   int64          `json:"conversation_count"`
	Scope       []ProjectScope `json:"scope"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ProjectScope is one scope rule of a project (mirrors company_scope; parsing
// reuses ParseScopeInput so both axes share the same guardrails).
type ProjectScope struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Kind      string    `json:"kind"` // domain|ip|cidr|icp|keyword
	Domain    string    `json:"domain,omitempty"`
	Net       string    `json:"net,omitempty"`
	Value     string    `json:"value,omitempty"`
	Raw       string    `json:"raw"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const projectCols = `id, name, description, status, created_at, updated_at`

// ProjectStore holds project + project_scope queries.
type ProjectStore struct{ db *DB }

// Projects returns the project store.
func (d *DB) Projects() *ProjectStore { return &ProjectStore{db: d} }

func scanProject(row interface{ Scan(...any) error }) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// CreateProject inserts a new active project.
func (s *ProjectStore) CreateProject(name, description string) (Project, error) {
	return scanProject(s.db.QueryRow(`
INSERT INTO projects(name, description) VALUES (NULLIF($1,''), $2)
RETURNING `+projectCols, name, description))
}

// UpdateProject replaces the editable fields of a project.
func (s *ProjectStore) UpdateProject(id int64, name, description, status string) (Project, error) {
	return scanProject(s.db.QueryRow(`
UPDATE projects SET name=NULLIF($2,''), description=$3, status=$4
WHERE id=$1
RETURNING `+projectCols, id, name, description, status))
}

// DeleteProject removes a project. Scope rows cascade; tasks/conversations keep
// existing with project_id set to NULL (FK ON DELETE SET NULL).
func (s *ProjectStore) DeleteProject(id int64) error {
	_, err := s.db.Exec(`DELETE FROM projects WHERE id=$1`, id)
	return err
}

// GetProject returns one project enriched with counts and scope (empty Project
// when absent).
func (s *ProjectStore) GetProject(id int64) (Project, error) {
	p, err := scanProject(s.db.QueryRow(`SELECT `+projectCols+` FROM projects WHERE id=$1`, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return Project{}, nil
		}
		return Project{}, err
	}
	s.enrich(&p)
	return p, nil
}

// ListProjects returns all projects, newest first, with counts and scope.
func (s *ProjectStore) ListProjects() ([]Project, error) {
	rows, err := s.db.Query(`SELECT ` + projectCols + ` FROM projects ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		s.enrich(&p)
		out = append(out, p)
	}
	return out, rows.Err()
}

// enrich fills counts and scope best-effort: display metadata must never fail
// the whole listing.
func (s *ProjectStore) enrich(p *Project) {
	_ = s.db.QueryRow(`SELECT count(*) FROM tasks WHERE project_id=$1 AND deleted_at IS NULL`, p.ID).Scan(&p.TaskCount)
	_ = s.db.QueryRow(`SELECT count(*) FROM conversations WHERE project_id=$1`, p.ID).Scan(&p.ConvCount)
	rules, err := s.ProjectScopeRules(p.ID)
	if err == nil {
		p.Scope = rules
	}
}

// AddProjectScope parses multi-line scope text and inserts the rules. Parsing
// reuses ParseScopeInput (same guardrails as the company scope: no bare TLD,
// bounded CIDR sizes); duplicates are reported as skipped, not errors.
func (s *ProjectStore) AddProjectScope(projectID int64, lines []string, reason string) (added, skipped, invalid int, errMsgs []string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, err := ParseScopeInput(ScopeInput{Value: line})
		if err != nil {
			invalid++
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		inserted, err := s.insertScopeRule(projectID, parsed, reason)
		if err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		if !inserted {
			skipped++
			continue
		}
		added++
	}
	return added, skipped, invalid, errMsgs
}

func (s *ProjectStore) insertScopeRule(projectID int64, rule ParsedScope, reason string) (inserted bool, err error) {
	var res sql.Result
	switch rule.Kind {
	case "domain":
		res, err = s.db.Exec(`
INSERT INTO project_scope(project_id, kind, domain, raw, reason)
VALUES ($1, 'domain', $2, $3, NULLIF($4,''))
ON CONFLICT ON CONSTRAINT uq_project_scope_domain DO NOTHING`,
			projectID, rule.Domain, rule.Raw, reason)
	case "ip", "cidr":
		res, err = s.db.Exec(`
INSERT INTO project_scope(project_id, kind, net, raw, reason)
VALUES ($1, $2, $3::cidr, $4, NULLIF($5,''))
ON CONFLICT ON CONSTRAINT uq_project_scope_net DO NOTHING`,
			projectID, rule.Kind, rule.Net, rule.Raw, reason)
	case "icp", "keyword":
		res, err = s.db.Exec(`
INSERT INTO project_scope(project_id, kind, value, raw, reason)
VALUES ($1, $2, $3, $4, NULLIF($5,''))
ON CONFLICT (project_id, kind, value) WHERE kind IN ('icp','keyword') DO NOTHING`,
			projectID, rule.Kind, rule.Value, rule.Raw, reason)
	default:
		return false, fmt.Errorf("unknown scope kind: %s", rule.Kind)
	}
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteProjectScope removes one scope rule of a project.
func (s *ProjectStore) DeleteProjectScope(projectID, scopeID int64) error {
	_, err := s.db.Exec(`DELETE FROM project_scope WHERE id=$2 AND project_id=$1`, projectID, scopeID)
	return err
}

// ProjectScopeRules returns all scope rules of a project, newest last.
func (s *ProjectStore) ProjectScopeRules(projectID int64) ([]ProjectScope, error) {
	rows, err := s.db.Query(`
SELECT id, project_id, kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(value,''), raw, COALESCE(reason,''), created_at
FROM project_scope WHERE project_id=$1 ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectScope
	for rows.Next() {
		var r ProjectScope
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Kind, &r.Domain, &r.Net, &r.Value, &r.Raw, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TaskProjectID resolves a task's project; 0 = not attached.
func (d *DB) TaskProjectID(taskID int64) (int64, error) {
	var pid sql.NullInt64
	if err := d.QueryRow(`SELECT project_id FROM tasks WHERE id=$1`, taskID).Scan(&pid); err != nil {
		return 0, err
	}
	if !pid.Valid {
		return 0, nil
	}
	return pid.Int64, nil
}

// ConvProjectID resolves a conversation's project; 0 = not attached.
func (d *DB) ConvProjectID(convID int64) (int64, error) {
	var pid sql.NullInt64
	if err := d.QueryRow(`SELECT project_id FROM conversations WHERE id=$1`, convID).Scan(&pid); err != nil {
		return 0, err
	}
	if !pid.Valid {
		return 0, nil
	}
	return pid.Int64, nil
}

// insertTaskProjectScopeTx seeds a task's initial task_scope from its project's
// scope rules (planning context for round one, not an enforcement gate):
// domain→root_domain, ip/cidr→cidr. icp/keyword are hint-only rules and are not
// seeded. Runs inside the CreateTaskWithOptions transaction.
func insertTaskProjectScopeTx(tx *sql.Tx, taskID, projectID int64) error {
	_, err := tx.Exec(`
INSERT INTO task_scope(task_id, kind, domain, net, source, reason)
SELECT $1,
       CASE ps.kind WHEN 'domain' THEN 'root_domain' ELSE 'cidr' END,
       NULLIF(ps.domain, ''),
       ps.net,
       'project',
       '任务创建时继承项目范围(project_scope #' || ps.id || ')'
FROM project_scope ps
WHERE ps.project_id = $2 AND ps.kind IN ('domain','ip','cidr')
ON CONFLICT DO NOTHING`, taskID, projectID)
	return err
}
