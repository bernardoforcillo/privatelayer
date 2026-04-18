package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	managementv1 "github.com/bernardoforcillo/privatelayer/internal/gen/management/v1"
	"github.com/bernardoforcillo/privatelayer/internal/gen/management/v1/managementv1connect"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	apiURL string
	apiKey string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "admin",
		Short: "PrivateLayer admin CLI",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			viper.SetEnvPrefix("PRIVATELAYER")
			viper.AutomaticEnv()
			if apiURL == "" {
				apiURL = viper.GetString("API_URL")
			}
			if apiKey == "" {
				apiKey = viper.GetString("API_KEY")
			}
			if apiURL == "" {
				fmt.Fprintln(os.Stderr, "error: set --api-url or PRIVATELAYER_API_URL")
				os.Exit(1)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "Control plane URL")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "API key (or PRIVATELAYER_API_KEY)")

	orgsCmd := &cobra.Command{Use: "orgs", Short: "Manage organizations"}
	orgsCmd.AddCommand(orgsCreateCmd(), orgsGetCmd())

	nodesCmd := &cobra.Command{Use: "nodes", Short: "Manage nodes"}
	nodesCmd.AddCommand(nodesListCmd(), nodesDeleteCmd())

	keysCmd := &cobra.Command{Use: "keys", Short: "Manage pre-auth keys"}
	keysCmd.AddCommand(keysCreateCmd(), keysListCmd(), keysRevokeCmd())

	apikeysCmd := &cobra.Command{Use: "apikeys", Short: "Manage API keys"}
	apikeysCmd.AddCommand(apikeysCreateCmd(), apikeysListCmd(), apikeysRevokeCmd())

	rootCmd.AddCommand(orgsCmd, nodesCmd, keysCmd, apikeysCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newClient() managementv1connect.ManagementServiceClient {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: viper.GetBool("TLS_SKIP_VERIFY")},
			ForceAttemptHTTP2: true,
		},
	}
	url := apiURL
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	return managementv1connect.NewManagementServiceClient(httpClient, url)
}

func newRequest[T any](msg *T) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set("X-API-Key", apiKey)
	return req
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func orgsCreateCmd() *cobra.Command {
	var cidr string
	cmd := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Create a new organization",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			resp, err := newClient().CreateOrg(context.Background(), newRequest(&managementv1.CreateOrgRequest{
				Name: name,
				Cidr: cidr,
			}))
			if err != nil {
				return err
			}
			fmt.Printf("Created org: %s (slug: %s)\n", resp.Msg.Org.Name, resp.Msg.Org.Slug)
			fmt.Printf("API Key (save this — shown once): %s\n", resp.Msg.ApiKey)
			return nil
		},
	}
	cmd.Flags().String("name", "", "Org name (required)")
	cmd.Flags().StringVar(&cidr, "cidr", "10.0.0.0/8", "Network CIDR")
	cmd.MarkFlagRequired("name")
	return cmd
}

func orgsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <slug>",
		Short: "Get an organization by slug",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().GetOrg(context.Background(), newRequest(&managementv1.GetOrgRequest{
				Slug: args[0],
			}))
			if err != nil {
				return err
			}
			printJSON(resp.Msg.Org)
			return nil
		},
	}
}

func nodesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List nodes in the org",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().ListNodes(context.Background(), newRequest(&managementv1.ListNodesRequest{}))
			if err != nil {
				return err
			}
			printJSON(resp.Msg.Nodes)
			return nil
		},
	}
}

func nodesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <node-id>",
		Short: "Delete a node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient().DeleteNode(context.Background(), newRequest(&managementv1.DeleteNodeRequest{Id: args[0]}))
			if err != nil {
				return err
			}
			fmt.Println("Node deleted.")
			return nil
		},
	}
}

func keysCreateCmd() *cobra.Command {
	var reusable, ephemeral bool
	var expires string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a pre-auth key",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().CreatePreAuthKey(context.Background(), newRequest(&managementv1.CreatePreAuthKeyRequest{
				Reusable:  reusable,
				Ephemeral: ephemeral,
				ExpiresIn: expires,
			}))
			if err != nil {
				return err
			}
			fmt.Printf("Pre-auth key: %s\n", resp.Msg.Key.Key)
			if resp.Msg.Key.ExpiresAt > 0 {
				fmt.Printf("Expires: %s\n", time.UnixMilli(resp.Msg.Key.ExpiresAt).Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&reusable, "reusable", false, "Key can be used multiple times")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "Node removed when disconnected")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry duration e.g. 24h")
	return cmd
}

func keysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().ListPreAuthKeys(context.Background(), newRequest(&managementv1.ListPreAuthKeysRequest{}))
			if err != nil {
				return err
			}
			printJSON(resp.Msg.Keys)
			return nil
		},
	}
}

func keysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "revoke <key>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient().RevokePreAuthKey(context.Background(), newRequest(&managementv1.RevokePreAuthKeyRequest{Key: args[0]}))
			if err != nil {
				return err
			}
			fmt.Println("Key revoked.")
			return nil
		},
	}
}

func apikeysCreateCmd() *cobra.Command {
	var desc, expires string
	cmd := &cobra.Command{
		Use:  "create",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().CreateAPIKey(context.Background(), newRequest(&managementv1.CreateAPIKeyRequest{
				Description: desc,
				ExpiresIn:   expires,
			}))
			if err != nil {
				return err
			}
			fmt.Printf("API Key (save this — shown once): %s\n", resp.Msg.RawKey)
			return nil
		},
	}
	cmd.Flags().StringVar(&desc, "description", "", "Key description")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry duration e.g. 720h")
	return cmd
}

func apikeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := newClient().ListAPIKeys(context.Background(), newRequest(&managementv1.ListAPIKeysRequest{}))
			if err != nil {
				return err
			}
			printJSON(resp.Msg.Keys)
			return nil
		},
	}
}

func apikeysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "revoke <id>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient().RevokeAPIKey(context.Background(), newRequest(&managementv1.RevokeAPIKeyRequest{Id: args[0]}))
			if err != nil {
				return err
			}
			fmt.Println("API key revoked.")
			return nil
		},
	}
}
