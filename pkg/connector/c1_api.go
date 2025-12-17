package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// c1TokenResponse represents the OAuth2 token response from ConductorOne
type c1TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// c1ApiClient handles API calls to ConductorOne
type c1ApiClient struct {
	clientID      string
	clientSecret  string
	appID         string
	entitlementID string
	httpClient    *http.Client
	tokenCache    *c1TokenCache
}

type c1TokenCache struct {
	token     string
	expiresAt time.Time
}

// getBearerToken retrieves a bearer token from ConductorOne using client credentials
// The token host is extracted from the client ID format: clientName@tenant.conductor.one
func (c *c1ApiClient) getBearerToken(ctx context.Context) (string, error) {
	l := ctxzap.Extract(ctx)

	// Check if we have a cached valid token
	if c.tokenCache != nil && time.Now().Before(c.tokenCache.expiresAt) {
		return c.tokenCache.token, nil
	}

	// Extract tenant from client ID (format: clientName@tenant.conductor.one or clientName@tenant.conductor.one/path)
	parts := strings.Split(c.clientID, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid client ID format, expected 'clientName@tenant.conductor.one'")
	}
	// Remove any path suffix (e.g., /pcc) to get just the domain
	tenant := strings.Split(parts[1], "/")[0]

	// Build token URL
	tokenURL := fmt.Sprintf("https://%s/auth/v1/token", tenant)

	// Prepare request body
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	l.Debug("requesting bearer token from ConductorOne", zap.String("token_url", tokenURL))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token: status %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp c1TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	// Cache the token (expire 5 minutes before actual expiry for safety)
	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn == 0 {
		expiresIn = 3600 * time.Second // Default to 1 hour if not specified
	}
	c.tokenCache = &c1TokenCache{
		token:     tokenResp.AccessToken,
		expiresAt: time.Now().Add(expiresIn - 5*time.Minute),
	}

	l.Debug("successfully obtained bearer token", zap.Time("expires_at", c.tokenCache.expiresAt))
	return tokenResp.AccessToken, nil
}

// searchAppUsersRequest represents the request body for searching app users
type searchAppUsersRequest struct {
	AppID string `json:"appId"`
	Query string `json:"query"`
}

// appUser represents an app user in the search response
type appUser struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
}

// appUserListItem represents an item in the search response list
// Each item contains an appUser object
type appUserListItem struct {
	AppUser appUser `json:"appUser"`
}

// searchAppUsersResponse represents the response from searching app users
// The API returns list as an array of objects, each containing an appUser field
type searchAppUsersResponse struct {
	List []appUserListItem `json:"list"`
}

// revokeEntitlementRequest represents the request body for revoking an entitlement
type revokeEntitlementRequest struct {
	AppID            string `json:"appId"`
	AppEntitlementID string `json:"appEntitlementId"`
	AppUserID        string `json:"appUserId"`
}

// revokeEntitlementResponse represents the response from revoking an entitlement
type revokeEntitlementResponse struct {
	TaskID string `json:"taskId,omitempty"`
}

// searchAppUser searches for an app user by query (SQL Server login name) and returns the ConductorOne appUserId
func (c *c1ApiClient) searchAppUser(ctx context.Context, token, tenant, query string) (string, error) {
	l := ctxzap.Extract(ctx)

	// Build search API URL
	searchURL := fmt.Sprintf("https://%s/api/v1/search/app_users", tenant)

	// Prepare search request body
	searchRequest := searchAppUsersRequest{
		AppID: c.appID,
		Query: query, // SQL Server login name (e.g., "DOMAIN\user.name")
	}

	jsonBody, err := json.Marshal(searchRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal search request body: %w", err)
	}

	// Create search request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", fmt.Errorf("failed to create search request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	l.Debug("searching for app user in ConductorOne",
		zap.String("url", searchURL),
		zap.String("query", query))

	// Make the search request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make search request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read search response body: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("app user search failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Log the raw response for debugging
	l.Debug("app user search response",
		zap.String("query", query),
		zap.String("response_body", string(body)))

	// Parse search response
	var searchResp searchAppUsersResponse
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return "", fmt.Errorf("failed to parse search response: %w, body: %s", err, string(body))
	}

	// Check if we found any app users
	if len(searchResp.List) == 0 {
		return "", fmt.Errorf("app user not found for query: %s", query)
	}

	// Use the first matching app user - the ID is inside the appUser object
	appUserID := searchResp.List[0].AppUser.ID
	if appUserID == "" {
		// Log the full response structure to help debug
		l.Warn("app user found but ID is empty",
			zap.String("query", query),
			zap.Any("app_user", searchResp.List[0].AppUser),
			zap.String("response_body", string(body)))
		return "", fmt.Errorf("app user found but ID is empty for query: %s, response: %s", query, string(body))
	}

	l.Debug("found app user",
		zap.String("query", query),
		zap.String("app_user_id", appUserID),
		zap.String("display_name", searchResp.List[0].AppUser.DisplayName))

	return appUserID, nil
}

// revokeEntitlementForUser revokes a ConductorOne app entitlement for a user
// This can be called independently of auto-delete to remove users from the "App Access" entitlement
// The userExternalID should be the SQL Server login name (e.g., "DOMAIN\user.name")
// This function first searches for the app user to get the ConductorOne appUserId, then revokes the entitlement
func (c *c1ApiClient) revokeEntitlementForUser(ctx context.Context, userExternalID string) error {
	if c.clientID == "" || c.clientSecret == "" || c.appID == "" || c.entitlementID == "" {
		// Credentials not provided, skip
		return nil
	}

	l := ctxzap.Extract(ctx)
	l.Debug("removing user from ConductorOne app entitlement",
		zap.String("app_id", c.appID),
		zap.String("entitlement_id", c.entitlementID),
		zap.String("user_external_id", userExternalID))

	// Get bearer token
	token, err := c.getBearerToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get bearer token: %w", err)
	}

	// Extract tenant from client ID (format: clientName@tenant.conductor.one or clientName@tenant.conductor.one/path)
	parts := strings.Split(c.clientID, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid client ID format, expected 'clientName@tenant.conductor.one'")
	}
	// Remove any path suffix (e.g., /pcc) to get just the domain
	tenant := strings.Split(parts[1], "/")[0]

	// Step 1: Search for the app user to get the ConductorOne appUserId
	appUserID, err := c.searchAppUser(ctx, token, tenant, userExternalID)
	if err != nil {
		return fmt.Errorf("failed to search for app user: %w", err)
	}

	// Step 2: Revoke the entitlement using the appUserId
	// Build API URL (endpoint: POST /api/v1/task/revoke)
	apiURL := fmt.Sprintf("https://%s/api/v1/task/revoke", tenant)

	// Prepare request body
	requestBody := revokeEntitlementRequest{
		AppID:            c.appID,
		AppEntitlementID: c.entitlementID,
		AppUserID:        appUserID, // Use the ConductorOne appUserId from the search
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return fmt.Errorf("failed to create API request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	l.Debug("calling ConductorOne API to remove user from entitlement",
		zap.String("url", apiURL),
		zap.String("app_id", c.appID),
		zap.String("entitlement_id", c.entitlementID),
		zap.String("app_user_id", appUserID),
		zap.String("user_external_id", userExternalID),
		zap.String("request_body", string(jsonBody)))

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make API request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error messages
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		// Check if this is a 409 "duplicate ticket" error, which means the entitlement
		// is already being revoked (likely from a previous revoke call). This is not an error.
		if resp.StatusCode == http.StatusConflict {
			var errorResp struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(body, &errorResp); err == nil {
				if errorResp.Message != "" && (strings.Contains(errorResp.Message, "duplicate ticket") || strings.Contains(errorResp.Message, "duplicate")) {
					l.Info("entitlement revocation already in progress (duplicate ticket), treating as success",
						zap.String("app_user_id", appUserID),
						zap.String("user_external_id", userExternalID),
						zap.String("message", errorResp.Message))
					return nil
				}
			}
		}

		l.Error("failed to remove user from entitlement",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(body)),
			zap.String("url", apiURL),
			zap.String("app_id", c.appID),
			zap.String("entitlement_id", c.entitlementID),
			zap.String("app_user_id", appUserID))
		return fmt.Errorf("API request failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response (optional, but useful for logging)
	var apiResp revokeEntitlementResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		// Non-fatal: response parsing failed but the operation may have succeeded
		l.Warn("failed to parse API response, but status was OK", zap.Error(err))
	} else if apiResp.TaskID != "" {
		l.Info("successfully revoked entitlement",
			zap.String("app_user_id", appUserID),
			zap.String("user_external_id", userExternalID),
			zap.String("task_id", apiResp.TaskID))
	} else {
		l.Info("successfully revoked entitlement",
			zap.String("app_user_id", appUserID),
			zap.String("user_external_id", userExternalID))
	}

	return nil
}

// newC1ApiClient creates a new ConductorOne API client
func newC1ApiClient(clientID, clientSecret, appID, entitlementID string) *c1ApiClient {
	return &c1ApiClient{
		clientID:      clientID,
		clientSecret:  clientSecret,
		appID:         appID,
		entitlementID: entitlementID,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}
}
