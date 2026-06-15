package auth

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"api-fuzzer/internal/types"
)

const (
	envBearerToken  = "API_FUZZER_BEARER_TOKEN"
	envBasicUser    = "API_FUZZER_BASIC_USERNAME"
	envBasicPass    = "API_FUZZER_BASIC_PASSWORD"
	envAPIKeyPrefix = "API_FUZZER_API_KEY_"
	envOAuth2Prefix = "API_FUZZER_OAUTH2_"
)

func InjectAuth(req *types.HTTPRequest, authConfigs []*types.AuthConfig, userTokens map[string]string) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if req.Query == nil {
		req.Query = make(map[string]string)
	}
	if req.Cookies == nil {
		req.Cookies = make(map[string]string)
	}

	for _, ac := range authConfigs {
		if ac == nil {
			continue
		}

		token, err := resolveToken(ac, userTokens)
		if err != nil {
			return err
		}
		if token == "" {
			continue
		}

		authValue := buildAuthValue(ac, token)
		if err := injectIntoRequest(req, ac, authValue); err != nil {
			return err
		}
	}

	return nil
}

func resolveToken(ac *types.AuthConfig, userTokens map[string]string) (string, error) {
	if userTokens != nil {
		if t, ok := userTokens[ac.Name]; ok && t != "" {
			return t, nil
		}
	}

	if ac.EnvVar != "" {
		if t := os.Getenv(ac.EnvVar); t != "" {
			return t, nil
		}
	}

	switch ac.Type {
	case types.AuthTypeHTTPBearer:
		if t := os.Getenv(envBearerToken); t != "" {
			return t, nil
		}
	case types.AuthTypeHTTPBasic:
		username := ac.Username
		password := ac.Password
		if username == "" {
			username = os.Getenv(envBasicUser)
		}
		if password == "" {
			password = os.Getenv(envBasicPass)
		}
		if username != "" && password != "" {
			return encodeBasicAuth(username, password), nil
		}
	case types.AuthTypeAPIKey:
		envKey := envAPIKeyPrefix + strings.ToUpper(strings.ReplaceAll(ac.Name, "-", "_"))
		if t := os.Getenv(envKey); t != "" {
			return t, nil
		}
	case types.AuthTypeOAuth2:
		envKey := envOAuth2Prefix + strings.ToUpper(strings.ReplaceAll(ac.Name, "-", "_"))
		if t := os.Getenv(envKey); t != "" {
			return t, nil
		}
	}

	return "", nil
}

func buildAuthValue(ac *types.AuthConfig, token string) string {
	switch ac.Type {
	case types.AuthTypeHTTPBearer:
		scheme := "Bearer"
		if ac.Scheme != "" {
			scheme = ac.Scheme
		}
		return scheme + " " + token
	case types.AuthTypeHTTPBasic:
		if strings.HasPrefix(token, "Basic ") {
			return token
		}
		return "Basic " + token
	case types.AuthTypeOAuth2:
		scheme := "Bearer"
		if ac.Scheme != "" {
			scheme = ac.Scheme
		}
		return scheme + " " + token
	case types.AuthTypeAPIKey:
		return token
	default:
		return token
	}
}

func injectIntoRequest(req *types.HTTPRequest, ac *types.AuthConfig, value string) error {
	var name string
	switch ac.Type {
	case types.AuthTypeHTTPBearer, types.AuthTypeHTTPBasic, types.AuthTypeOAuth2:
		name = "Authorization"
	default:
		name = ac.Name
		if name == "" {
			return fmt.Errorf("auth config name is required for type %s", ac.Type)
		}
	}

	switch ac.In {
	case types.AuthInHeader:
		req.Headers[name] = value
	case types.AuthInQuery:
		req.Query[name] = value
	case types.AuthInCookie:
		req.Cookies[name] = value
	default:
		return fmt.Errorf("unsupported auth 'in' value: %s", ac.In)
	}

	return nil
}

func encodeBasicAuth(username, password string) string {
	combined := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(combined))
}

func EncodeBasicAuth(username, password string) string {
	return encodeBasicAuth(username, password)
}
