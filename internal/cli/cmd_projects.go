package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/enigma-137/ven/internal/app"
	"github.com/enigma-137/ven/internal/domain"
	"github.com/enigma-137/ven/internal/environments"
	"github.com/enigma-137/ven/internal/projects"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/spf13/cobra"
)

func (c *cli) projectsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "projects",
		Aliases: []string{"project"},
		Short:   "Manage projects (works without the master password)",
		Long: "Manage projects inside the vault. A VEN project is only a named group of\n" +
			"environments; VEN never creates source code or files for it.",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			list, err := a.Projects.List(cmd.Context(), "")
			if err != nil {
				return err
			}
			if len(list) == 0 {
				c.infof("No projects yet. Create one with: ven projects create <name>")
				return nil
			}
			var rows [][]string
			for _, p := range list {
				rows = append(rows, []string{p.Name, p.Slug, strconv.Itoa(p.EnvironmentCount), ago(p.UpdatedAt), truncate(p.Description, 50)})
			}
			table(c.env.Out, []string{"NAME", "SLUG", "ENVS", "UPDATED", "DESCRIPTION"}, rows)
			return nil
		},
	})

	var desc string
	var envs []string
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a project with its environments",
		Example: `  ven projects create "Billing API"
  ven projects create web --description "Marketing site" --envs development,production
  ven projects create scratch --envs ""`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			var names []string
			for _, e := range envs {
				if e = strings.TrimSpace(e); e != "" {
					names = append(names, e)
				}
			}
			p, created, err := a.Projects.Create(cmd.Context(), projects.CreateInput{Name: args[0], Description: desc, Environments: names})
			if err != nil {
				return err
			}
			var slugs []string
			for _, e := range created {
				slugs = append(slugs, e.Slug)
			}
			c.successf("Created project %s (slug: %s)", p.Name, p.Slug)
			if len(slugs) > 0 {
				c.infof("  Environments: %s", strings.Join(slugs, ", "))
			}
			return nil
		},
	}
	create.Flags().StringVar(&desc, "description", "", "optional description")
	create.Flags().StringSliceVar(&envs, "envs", projects.DefaultEnvironments, "environments to create (comma-separated; empty for none)")
	cmd.AddCommand(create)

	cmd.AddCommand(&cobra.Command{
		Use:   "rename <project> <name>",
		Short: "Rename a project (its slug follows the new name)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			p, err := a.Projects.Rename(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			c.successf("Renamed project to %s (slug: %s)", p.Name, p.Slug)
			return nil
		},
	})

	var newDesc string
	update := &cobra.Command{
		Use:   "update <project> --description <text>",
		Short: "Update a project's description",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("description") {
				return usageErr("nothing to update: pass --description")
			}
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			p, err := a.Projects.Update(cmd.Context(), args[0], projects.UpdateInput{Description: &newDesc})
			if err != nil {
				return err
			}
			c.successf("Updated %s", p.Name)
			return nil
		},
	}
	update.Flags().StringVar(&newDesc, "description", "", "new description (empty to clear)")
	cmd.AddCommand(update)

	var yes bool
	del := &cobra.Command{
		Use:   "delete <project>",
		Short: "Delete a project with all of its environments and variables",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			p, err := a.Projects.Resolve(ctx, args[0])
			if err != nil {
				return err
			}
			envList, err := storage.ListEnvironments(ctx, a.DB, p.ID)
			if err != nil {
				return err
			}
			vars := 0
			for _, e := range envList {
				vars += e.VariableCount
			}
			if !yes {
				if !c.env.Term.Interactive() {
					return needInput("deleting a project needs confirmation: pass --yes in non-interactive mode")
				}
				c.warnf("This permanently deletes project %s with %d environment(s) and %d variable(s).", p.Name, len(envList), vars)
				ans, err := c.env.Term.ReadLine(fmt.Sprintf("Type the project slug (%s) to confirm: ", p.Slug))
				if err != nil {
					return err
				}
				if strings.TrimSpace(ans) != p.Slug {
					return ErrCancelled
				}
			}
			if _, err := a.Projects.Delete(ctx, p.Slug); err != nil {
				return err
			}
			c.successf("Deleted project %s", p.Name)
			return nil
		},
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.AddCommand(del)
	return cmd
}

func (c *cli) envsCommand() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:     "envs",
		Aliases: []string{"env", "environments"},
		Short:   "Manage a project's environments (works without the master password)",
	}
	cmd.PersistentFlags().StringVarP(&project, "project", "p", "", "project slug or name (required)")

	needProject := func() error {
		if project == "" {
			return usageErr("--project is required")
		}
		return nil
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list --project <project>",
		Short: "List environments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := needProject(); err != nil {
				return err
			}
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			p, list, err := a.Environments.List(cmd.Context(), project)
			if err != nil {
				return err
			}
			if len(list) == 0 {
				c.infof("%s has no environments. Create one with: ven envs create <name> --project %s", p.Name, p.Slug)
				return nil
			}
			var rows [][]string
			for _, e := range list {
				rows = append(rows, []string{e.Name, e.Slug, strconv.Itoa(e.VariableCount), ago(e.UpdatedAt)})
			}
			table(c.env.Out, []string{"NAME", "SLUG", "VARIABLES", "UPDATED"}, rows)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "create <name> --project <project>",
		Short: "Create a custom environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := needProject(); err != nil {
				return err
			}
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			e, err := a.Environments.Create(cmd.Context(), project, args[0])
			if err != nil {
				return err
			}
			c.successf("Created environment %s (slug: %s)", e.Name, e.Slug)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rename <environment> <name> --project <project>",
		Short: "Rename an environment",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := needProject(); err != nil {
				return err
			}
			a, err := c.requireInitialized(cmd.Context())
			if err != nil {
				return err
			}
			e, err := a.Environments.Rename(cmd.Context(), project, args[0], args[1])
			if err != nil {
				return err
			}
			c.successf("Renamed environment to %s (slug: %s)", e.Name, e.Slug)
			return nil
		},
	})

	var yes bool
	del := &cobra.Command{
		Use:   "delete <environment> --project <project>",
		Short: "Delete an environment and its variables",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := needProject(); err != nil {
				return err
			}
			ctx := cmd.Context()
			a, err := c.requireInitialized(ctx)
			if err != nil {
				return err
			}
			p, e, err := a.Environments.Resolve(ctx, project, args[0])
			if err != nil {
				return err
			}
			if !yes {
				if !c.env.Term.Interactive() {
					return needInput("deleting an environment needs confirmation: pass --yes in non-interactive mode")
				}
				c.warnf("This permanently deletes %s/%s and its %d variable(s).", p.Slug, e.Slug, e.VariableCount)
				ans, err := c.env.Term.ReadLine(fmt.Sprintf("Type the environment slug (%s) to confirm: ", e.Slug))
				if err != nil {
					return err
				}
				if strings.TrimSpace(ans) != e.Slug {
					return ErrCancelled
				}
			}
			if _, err := a.Environments.Delete(ctx, p.Slug, e.Slug); err != nil {
				return err
			}
			c.successf("Deleted environment %s/%s", p.Slug, e.Slug)
			return nil
		},
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.AddCommand(del)
	return cmd
}

// target describes a resolved (or to-be-created) project/environment pair.
type target struct {
	project       projects.Project
	env           environments.Environment
	createProject string // non-empty: project to create before writing
	createEnv     string // non-empty: environment to create before writing
}

func (t target) label() string {
	p, e := t.project.Slug, t.env.Slug
	if t.createProject != "" {
		p = domain.Slugify(t.createProject) + " (new)"
	}
	if t.createEnv != "" {
		e = domain.Slugify(t.createEnv) + " (new)"
	}
	return p + "/" + e
}

// resolveTarget finds the project and environment from flags, prompting
// when interactive. With allowCreate, missing ones may be scheduled for
// creation (after confirmation or with createFlag).
func (c *cli) resolveTarget(ctx context.Context, a *app.App, projectRef, envRef string, allowCreate, createFlag bool) (target, error) {
	var t target
	interactive := c.env.Term.Interactive()

	if projectRef == "" {
		if !interactive {
			return t, needInput("--project is required in non-interactive mode")
		}
		list, err := a.Projects.List(ctx, "")
		if err != nil {
			return t, err
		}
		if len(list) == 0 {
			return t, errors.New("no projects yet: create one with `ven projects create <name>`")
		}
		var items []string
		for _, p := range list {
			items = append(items, fmt.Sprintf("%s (%s)", p.Name, p.Slug))
		}
		i, err := c.choose("Projects:", items)
		if err != nil {
			return t, err
		}
		t.project = list[i]
	} else {
		p, err := a.Projects.Resolve(ctx, projectRef)
		switch {
		case err == nil:
			t.project = p
		case errors.Is(err, storage.ErrNotFound) && allowCreate:
			if err := c.offerCreate(fmt.Sprintf("Project %q does not exist. Create it?", projectRef), createFlag); err != nil {
				return t, err
			}
			t.createProject = projectRef
		default:
			return t, err
		}
	}

	if envRef == "" {
		if !interactive {
			return t, needInput("--env is required in non-interactive mode")
		}
		if t.createProject != "" {
			return t, needInput("--env is required when creating a project")
		}
		list, err := storage.ListEnvironments(ctx, a.DB, t.project.ID)
		if err != nil {
			return t, err
		}
		if len(list) == 0 {
			return t, fmt.Errorf("project %s has no environments: create one with `ven envs create <name> --project %s`", t.project.Slug, t.project.Slug)
		}
		var items []string
		for _, e := range list {
			items = append(items, fmt.Sprintf("%s (%d variables)", e.Slug, e.VariableCount))
		}
		i, err := c.choose("Environments in "+t.project.Slug+":", items)
		if err != nil {
			return t, err
		}
		t.env = list[i]
		return t, nil
	}
	if t.createProject != "" {
		t.createEnv = envRef
		return t, nil
	}
	e, err := environments.ResolveIn(ctx, a.DB, t.project.ID, envRef)
	switch {
	case err == nil:
		t.env = e
	case errors.Is(err, storage.ErrNotFound) && allowCreate:
		if err := c.offerCreate(fmt.Sprintf("Environment %q does not exist in %s. Create it?", envRef, t.project.Slug), createFlag); err != nil {
			return t, err
		}
		t.createEnv = envRef
	default:
		return t, err
	}
	return t, nil
}

func (c *cli) offerCreate(question string, createFlag bool) error {
	if createFlag {
		return nil
	}
	if !c.env.Term.Interactive() {
		return needInput("%s Pass --create to create it in non-interactive mode", strings.TrimSuffix(question, " Create it?"))
	}
	ok, err := c.confirm(question, false)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCancelled
	}
	return nil
}

// materialize creates any scheduled project/environment and returns the
// environment ID plus a cleanup function that removes what was created.
func (c *cli) materialize(ctx context.Context, a *app.App, t *target) (cleanup func(), err error) {
	cleanup = func() {}
	if t.createProject != "" {
		p, envs, err := a.Projects.Create(ctx, projects.CreateInput{Name: t.createProject, Environments: []string{t.createEnv}})
		if err != nil {
			return cleanup, err
		}
		t.project, t.env = p, envs[0]
		t.createProject, t.createEnv = "", ""
		slug := p.Slug
		return func() { _, _ = a.Projects.Delete(context.Background(), slug) }, nil
	}
	if t.createEnv != "" {
		e, err := a.Environments.Create(ctx, t.project.Slug, t.createEnv)
		if err != nil {
			return cleanup, err
		}
		t.env = e
		t.createEnv = ""
		ps, es := t.project.Slug, e.Slug
		return func() { _, _ = a.Environments.Delete(context.Background(), ps, es) }, nil
	}
	return cleanup, nil
}
