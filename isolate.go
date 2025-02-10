// pkg/filter/action/isolate.go

package action

// IsolateAction defines the action for isolating a machine using Windows Firewall rules
type IsolateAction struct {
    // WhitelistDomains contains domains that should remain accessible
    WhitelistDomains []string `json:"whitelist_domains,omitempty" yaml:"whitelist_domains,omitempty"`
    // IsolationName is a unique identifier for the isolation rule set
    IsolationName string `json:"isolation_name,omitempty" yaml:"isolation_name,omitempty"`
}

// Isolate creates Windows Firewall rules to isolate the machine while maintaining access to whitelisted domains
func Isolate(action *IsolateAction) error {
    // Create inbound block rule
    err := createBlockRule("Fibratus-Isolation-In", "in")
    if err != nil {
        return fmt.Errorf("failed to create inbound block rule: %v", err)
    }

    // Create outbound block rule
    err = createBlockRule("Fibratus-Isolation-Out", "out") 
    if err != nil {
        return fmt.Errorf("failed to create outbound block rule: %v", err)
    }

    // Create allow rules for whitelisted domains
    for _, domain := range action.WhitelistDomains {
        err = createAllowRule(domain)
        if err != nil {
            return fmt.Errorf("failed to create allow rule for domain %s: %v", domain, err)
        }
    }

    return nil
}

// Unisolate removes all Fibratus isolation firewall rules
func Unisolate() error {
    // Delete all Fibratus isolation rules
    err := removeIsolationRules()
    if err != nil {
        return fmt.Errorf("failed to remove isolation rules: %v", err)
    }
    return nil
}

// Helper functions to interact with Windows Firewall
func createBlockRule(name string, direction string) error {
    cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
        "name=" + name,
        "dir=" + direction,
        "action=block")
    return cmd.Run()
}

func createAllowRule(domain string) error {
    cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
        "name=Fibratus-Allow-" + domain,
        "dir=out",
        "action=allow",
        "remoteip=" + domain)
    return cmd.Run()
}

func removeIsolationRules() error {
    cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
        "name=all",
        "dir=in",
        "remoteip=any")
    if err := cmd.Run(); err != nil {
        return err
    }

    cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
        "name=all", 
        "dir=out",
        "remoteip=any")
    return cmd.Run()
}
