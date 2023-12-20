package utils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v4"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/logharbour/logharbour"
)

// Capabilities representing user capabilities.
type Capabilities struct {
	Capability []string `json:"capability"`
}

// IsCapable checks if a user, identified by the provided access token, possesses all the specified capabilities.
// It utilizes the provided GoCloak client, service information, and capabilities JSON to make the determination.
// The function decodes the access token, extracts roles from the claims, and compares them with the specified capabilities.
// If the user has all the required capabilities, it returns true; otherwise, it returns false.
// An error is returned if there are issues with decoding the token or handling the provided data.
func IsCapable(s *service.Service, accessToken string, capabilitiesJson []byte) (bool, error) {
	l := s.LogHarbour
	// Extracting the GoCloak client from the service dependencies
	gcClient := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	// Extracting the relam from the service dependencies
	relam := s.Dependencies["realm"].(string)

	_, claims, err := gcClient.DecodeAccessToken(context.Background(), accessToken, relam)
	if err != nil {
		l.Debug0().LogDebug("error while decoding token: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		return false, err
	}

	// Extract roles from the claims
	roles, err := extractRoles(*claims)
	if err != nil {
		l.Debug0().LogDebug("Error while extracting realm_access from token claims ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
	}

	var capabilities Capabilities

	if err = json.Unmarshal(capabilitiesJson, &capabilities); err != nil {
		l.Debug0().LogDebug("Error while unmarshlaing capabilitiesJson ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		return false, err
	}

	capabilitiesMap := make(map[string]bool)
	for _, capability := range capabilities.Capability {
		capabilitiesMap[capability] = true
	}

	allCapabilitiesPresent := false
	for _, role := range roles {
		if _, exists := capabilitiesMap[role]; exists {
			allCapabilitiesPresent = true
			continue
		}
	}
	return allCapabilitiesPresent, nil

}

// Extract roles from the claims
func extractRoles(claims jwt.MapClaims) ([]string, error) {
	var roles []string
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if roleClaims, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range roleClaims {
				if r, ok := role.(string); ok {
					roles = append(roles, r)
				}
			}
		}
	} else {
		return nil, fmt.Errorf("error while extracting realm_access from token claims")
	}
	return roles, nil
}
