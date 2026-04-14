// Package workloadidentity implements Azure AD workload identity token acquisition using MSAL
// with Kubernetes TokenRequest-based client assertion. No pod filesystem/env access is used.
package workloadidentity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"mosaic/config"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	confidential "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

const (
	authorityTemplate = "https://login.microsoftonline.com/%s/"
)

var (
	// ErrNoClientID indicates missing Azure AD application (client) ID in config.
	ErrNoClientID = errors.New("missing client id")
	// ErrNoTenantID indicates missing Azure AD tenant ID in config.
	ErrNoTenantID = errors.New("missing tenant id")
	// ErrNoServiceAccount indicates missing Kubernetes service account name in config.
	ErrNoServiceAccount = errors.New("missing service account name")
	// ErrNoKubeClient indicates missing Kubernetes client for TokenRequest.
	ErrNoKubeClient = errors.New("missing kube client")
	// ErrFailedToObtainSAToken indicates failure to obtain a service account token from Kubernetes.
	ErrFailedToObtainSAToken = errors.New("failed to obtain service account token")
	// ErrFailedTokenAcquisition indicates failure to acquire an Azure access token using MSAL.
	ErrFailedTokenAcquisition = errors.New("failed to acquire token with msal")
	// ErrInvalidScopes indicates invalid scopes provided for token acquisition.
	ErrInvalidScopes = errors.New("invalid scopes")
)

// WorkloadIdentity handles obtaining Azure access tokens using Kubernetes service account tokens.
type WorkloadIdentity struct {
	// Azure AD application (client) ID and tenant ID.
	ClientID string
	TenantID string

	// Kubernetes service account identity.
	Namespace       string
	ServiceAccount  string
	Audience        string // Typically "api://AzureADTokenExchange" for Azure workload identity
	RequestedExpiry time.Duration

	// Kubernetes client (required for token requests).
	KubeClient kubernetes.Interface

	logger *zap.Logger

	// Cached Azure access tokens per scope.
	mu        sync.Mutex
	cache     map[string]tokenEntry
	clockSkew time.Duration

	// MSAL confidential client initialized with assertion callback that uses Kubernetes TokenRequest.
	msalClient confidential.Client
}

type tokenEntry struct {
	token string
	exp   time.Time
}

// New constructs a WorkloadIdentity instance from Config.
func New(cfg *config.Config, kubeClient kubernetes.Interface) (*WorkloadIdentity, error) {
	if cfg.WorkloadIdentity.ServiceAccount == "" {
		return nil, ErrNoServiceAccount
	}

	if cfg.EntraTenantID == "" {
		return nil, ErrNoTenantID
	}

	if cfg.WorkloadIdentity.ClientID == "" {
		return nil, ErrNoClientID
	}

	if kubeClient == nil {
		return nil, ErrNoKubeClient
	}
	w := &WorkloadIdentity{
		ClientID:        cfg.WorkloadIdentity.ClientID,
		TenantID:        cfg.EntraTenantID,
		Namespace:       cfg.WorkloadIdentity.Namespace,
		ServiceAccount:  cfg.WorkloadIdentity.ServiceAccount,
		Audience:        cfg.WorkloadIdentity.Audience,
		RequestedExpiry: cfg.WorkloadIdentityExpiry(),
		KubeClient:      kubeClient,
		logger:          zap.L(),
		clockSkew:       60 * time.Second,
		cache:           make(map[string]tokenEntry),
	}

	if err := w.initMSALClient(); err != nil {
		return nil, err
	}

	return w, nil
}

// AcquireAzureAccessToken obtains an Azure access token for the specified scopes.
func (w *WorkloadIdentity) AcquireAzureAccessToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	key, err := w.scopeKey(scopes)
	if err != nil {
		return "", time.Time{}, err
	}

	// First attempt to get token from cache
	if token, exp, ok := w.getFromCache(key); ok {
		return token, exp, nil
	}

	// On cache miss, acquire new token via MSAL using federated assertion
	res, err := w.msalClient.AcquireTokenByCredential(ctx, scopes, confidential.WithTenantID(w.TenantID))
	if err != nil {
		w.logger.Error("msal_token_acquisition_failed", zap.Error(err))
		return "", time.Time{}, ErrFailedTokenAcquisition
	}

	// Set the acquired token in cache
	w.setCache(key, res.AccessToken, res.ExpiresOn)
	return res.AccessToken, res.ExpiresOn, nil
}

// AcquireAssertionCredential returns an azidentity.ClientAssertionCredential that uses a callback to obtain Kubernetes service account tokens for client assertion.
func (w *WorkloadIdentity) AcquireAssertionCredential() (*azidentity.ClientAssertionCredential, error) {
	cred, err := azidentity.NewClientAssertionCredential(w.TenantID, w.ClientID, func(ctx context.Context) (string, error) {
		token, err := w.obtainServiceAccountToken(ctx)
		if err != nil {
			return "", err
		}
		return token, nil
	}, nil)

	if err != nil {
		return nil, err
	}

	return cred, nil
}

// Build a cache key from a scope array "scope1 scope2 scope3".
func (w *WorkloadIdentity) scopeKey(scopes []string) (string, error) {
	if len(scopes) == 0 {
		return "", ErrInvalidScopes
	}

	for _, s := range scopes {
		if strings.TrimSpace(s) == "" {
			return "", ErrInvalidScopes
		}
	}

	return strings.Join(scopes, " "), nil
}

// getFromCache returns the token if present and not expired (with skew), else false.
func (w *WorkloadIdentity) getFromCache(key string) (string, time.Time, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if entry, ok := w.cache[key]; ok {
		if time.Now().Add(w.clockSkew).Before(entry.exp) {
			return entry.token, entry.exp, true
		}
	}

	return "", time.Time{}, false
}

// setCache inserts/updates the cached token entry for a key.
func (w *WorkloadIdentity) setCache(key string, token string, exp time.Time) {
	w.mu.Lock()
	w.cache[key] = tokenEntry{token: token, exp: exp}
	w.mu.Unlock()
}

// obtainServiceAccountToken requests a token from Kubernetes using TokenRequest.
func (w *WorkloadIdentity) obtainServiceAccountToken(ctx context.Context) (string, error) {
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{w.Audience},
			ExpirationSeconds: ptrInt64(int64(w.RequestedExpiry.Seconds())),
		},
	}

	resp, err := w.KubeClient.CoreV1().ServiceAccounts(w.Namespace).CreateToken(ctx, w.ServiceAccount, tr, metav1.CreateOptions{})
	if err != nil {
		w.logger.Error("failed_to_obtain_sa_token", zap.Error(err))
		return "", err
	}

	return resp.Status.Token, nil
}

// initMSALClient constructs the MSAL confidential client using an assertion callback
// that obtains a Kubernetes service account token via TokenRequest.
func (w *WorkloadIdentity) initMSALClient() error {
	callback := func(cbCtx context.Context, _ confidential.AssertionRequestOptions) (string, error) {
		token, err := w.obtainServiceAccountToken(cbCtx)
		if err != nil {
			w.logger.Error("failed_to_obtain_sa_token", zap.Error(err))
			return "", ErrFailedToObtainSAToken
		}

		return token, nil
	}

	cred := confidential.NewCredFromAssertionCallback(callback)
	authority := fmt.Sprintf(authorityTemplate, w.TenantID)

	client, err := confidential.New(authority, w.ClientID, cred)
	if err != nil {
		return err
	}

	w.msalClient = client
	return nil
}

func ptrInt64(v int64) *int64 { return &v }
