package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"detector/modelapi"
	"detector/protection"
	"github.com/spf13/cobra"
)

var protectService string
var protectDetectionsURL string

var protectCmd = &cobra.Command{
	Use:   "protect",
	Short: "Show the response guide for a detector incident and optionally block one source IP",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runProtection(cmd.Context(), protectService, protectDetectionsURL)
	},
}

func init() {
	protectCmd.Flags().StringVar(&protectService, "service", "lag", "Model service: lag or live")
	protectCmd.Flags().StringVar(&protectDetectionsURL, "detections-url", "", "Override the local detector endpoint")
	rootCmd.AddCommand(protectCmd)
}

func runProtection(ctx context.Context, serviceName, override string) error {
	_, endpoint, err := resolveModelEndpoints(serviceName, "", override)
	if err != nil {
		return err
	}
	models := modelapi.NewClient("", endpoint)
	protectionService := protection.New(models)
	lookupCtx, stopLookup := context.WithTimeout(ctx, 8*time.Second)
	detections, err := models.DetectionsWithRules(lookupCtx)
	stopLookup()
	if err != nil {
		return err
	}
	incidents := detections.RecentIncidents
	if len(incidents) == 0 {
		incidents = detections.Incidents
	}
	if len(incidents) == 0 {
		fmt.Println("No detector incidents in the recent history. Forecast links and raw events are not protection targets.")
		return nil
	}
	fmt.Println("Recent detector incidents (only active incidents can enable automatic blocking):")
	active := make(map[string]bool, len(detections.Incidents))
	for _, item := range detections.Incidents {
		active[incidentSelectionKey(item)] = true
	}
	for i := len(incidents) - 1; i >= 0; i-- {
		item := incidents[i]
		state := "closed"
		if active[incidentSelectionKey(item)] {
			state = "active"
		}
		fmt.Printf("  %d. #%d %s sender node %d (%s)\n", len(incidents)-i, item.Incident, item.Family, item.Key, state)
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Select incident number (blank cancels): ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return nil
	}
	index, err := strconv.Atoi(choice)
	if err != nil || index < 1 || index > len(incidents) {
		return errors.New("invalid incident selection")
	}
	item := incidents[len(incidents)-index]
	adviceCtx, stopAdvice := context.WithTimeout(ctx, 10*time.Second)
	plan, err := protectionService.Advise(adviceCtx, protection.Identity{Family: item.Family, Incident: item.Incident, OpenedAt: item.T})
	stopAdvice()
	if err != nil {
		return err
	}
	fmt.Printf("\nResponse guide for incident #%d (%s):\n%s\n\n", plan.Incident, plan.Family, plan.Advice)
	if !plan.CanExecute {
		fmt.Printf("Automatic host block unavailable: %s\n", plan.Reason)
		return nil
	}
	fmt.Printf("Optional local containment: %s This cannot stop a distributed attack; the rule remains after Netwatch exits.\n", plan.Action)
	fmt.Printf("Type %s to execute, or press Enter to cancel: ", plan.Confirmation)
	confirmation, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	confirmation = strings.TrimSpace(confirmation)
	if confirmation == "" {
		return nil
	}
	executeCtx, stopExecute := context.WithTimeout(ctx, 90*time.Second)
	result, err := protectionService.Execute(executeCtx, plan.Token, confirmation)
	stopExecute()
	if err != nil {
		return err
	}
	fmt.Printf("Rule %s added for %s. Remove it later with:\n  %s\n", result.Rule, result.SourceIP, result.UndoCommand)
	return nil
}

func incidentSelectionKey(item modelapi.Incident) string {
	return fmt.Sprintf("%s|%d|%.9f", item.Family, item.Incident, item.T)
}
