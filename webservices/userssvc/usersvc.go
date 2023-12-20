package usersvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"

	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
	"github.com/remiges-tech/logharbour/logharbour"
)

// createUserRequest represents the structure for incoming user creation requests.
type createUserRequest struct {
	Username  string `json:"username" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Enabled   bool   `json:"enabled" validate:"required"`
	Realm     string `json:"realm"`
}

// createUserResponse represents the structure for outgoing user creation responses.
type createUserResponse struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Enabled   bool   `json:"enabled"`
}

// Capabilities representing user capabilities.
type Capabilities struct {
	Capability []string `json:"capability"`
}

// HandleCreateUserRequest is the handler function for creating a new user.
func HandleCreateUserRequest(c *gin.Context, s *service.Service) {
	l := s.LogHarbour
	// Log the start of execution
	l.Log("Starting execution of createUser")

	token, err := router.ExtractToken(c.GetHeader("Authorization"))
	if err != nil {
		// Log and respond to token extraction/validation error
		l.Debug0().LogDebug("Missing or incorrect Authorization header format:", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("token_missing"))
		return
	}

	capabilitiesJson := []byte(`{"capability": ["Admin"]}`)

	isCapable, err := isCapable(s, token, capabilitiesJson)
	if err != nil {
		l.LogActivity("Error while decodeing token:", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		fmt.Println("err", err)
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("token_verification_failed"))
		return
	}

	if !isCapable {
		l.LogActivity("Unauthorized user:", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("Unauthorized"))
		return
	}

	var user createUserRequest

	// Unmarshal JSON request into createUserRequest struct
	err = wscutils.BindJSON(c, &user)
	if err != nil {
		// Log and respond to JSON Unmarshalling error
		l.LogActivity("Error Unmarshalling JSON to struct:", logharbour.DebugInfo{Variables: map[string]interface{}{"Error": err.Error()}})
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("invalid_json"))
		return
	}

	// Validate the user creation request
	validationErrors := validateCreateUser(user, c)
	if len(validationErrors) > 0 {
		// Log and respond to validation errors
		l.Debug0().LogDebug("Validation errors:", logharbour.DebugInfo{Variables: map[string]interface{}{"validationErrors": validationErrors}})
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	// Create a new Keycloak user
	keycloakUser := gocloak.User{
		Username:  &user.Username,
		FirstName: &user.FirstName,
		LastName:  &user.LastName,
		Email:     &user.Email,
		Enabled:   &user.Enabled,
	}

	// Extracting the GoCloak client from the service dependencies for handling authentication and authorization.
	gcClient := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	// CreateUser creates the given user in the given realm and returns it's userID
	keyID, err := gcClient.CreateUser(c, token, user.Realm, keycloakUser)
	if err != nil {
		// Log and respond to Keycloak user creation errors
		l.LogActivity("Error while creating user:", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
		fmt.Println("err", err.Error())
		switch err.Error() {
		case "401 Unauthorized: HTTP 401 Unauthorized":
			l.Debug0().LogDebug("Unauthorized error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("Unauthorized"))
			return
		case "409 Conflict: User exists with same username":
			l.Debug0().LogDebug("User already exists error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("User_already_exists"))
			return
		case "404 Not Found: Realm not found.":
			l.Debug0().LogDebug("Realm not found error: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("Realm_not_found"))
			return
		default:
			l.Debug0().LogDebug("Unknown error occurred: ", logharbour.DebugInfo{Variables: map[string]interface{}{"error": err}})
			wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("unknown"))
			return
		}
	}

	// Create a response structure
	createUserResponse := createUserResponse{
		ID:        keyID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Enabled:   user.Enabled,
	}

	// Send success response
	wscutils.SendSuccessResponse(c, &wscutils.Response{Data: createUserResponse})

	// Log the completion of execution
	l.LogActivity("Finished execution of createUser", map[string]string{"URl": "/rigel/user", "Timestamp": time.Now().Format("2006-01-02 15:04:05")})
}

// validateCreateUser performs validation for the createUserRequest.
func validateCreateUser(user createUserRequest, c *gin.Context) []wscutils.ErrorMessage {
	// Validate the request body
	validationErrors := wscutils.WscValidate(user, user.getValsForUser)

	// If there are standard validation errors, return them and skip custom validations
	if len(validationErrors) > 0 {
		return validationErrors
	}

	// Perform additional custom validations if needed

	return validationErrors
}

// getValsForUser returns validation error details based on the field and tag.
func (u *createUserRequest) getValsForUser(err validator.FieldError) []string {
	var vals []string

	switch err.Field() {
	case "Username":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, u.Username)
		}
	case "Email":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, u.Email)
		case "email":
			vals = append(vals, "valid email format")
			vals = append(vals, u.Email)
		}
	case "Enabled":
		switch err.Tag() {
		case "required":
			vals = append(vals, "non-empty")
			vals = append(vals, strconv.FormatBool(u.Enabled))
		}
	}

	return vals
}

// isCapable checks if a user, identified by the provided access token, possesses all the specified capabilities.
// It utilizes the provided GoCloak client, service information, and capabilities JSON to make the determination.
// The function decodes the access token, extracts roles from the claims, and compares them with the specified capabilities.
// If the user has all the required capabilities, it returns true; otherwise, it returns false.
// An error is returned if there are issues with decoding the token or handling the provided data.
func isCapable(s *service.Service, accessToken string, capabilitiesJson []byte) (bool, error) {
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
