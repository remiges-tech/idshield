package user

import (
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/remiges-tech/alya/router"
	"github.com/remiges-tech/alya/service"
	"github.com/remiges-tech/alya/wscutils"
)

type UserVo struct {
	Realm    string                     `json:"realm" validate:"required,min=4"`
	User     gocloak.User               `json:"user,omitempty"`
	Params   gocloak.GetUsersParams     `json:"params,omitempty"`
	Password gocloak.SetPasswordRequest `json:"password,omitempty"`
}

type UserResponseVo struct {
	Id            *string              `json:"id,omitempty"`
	Username      *string              `json:"username,omitempty"`
	Email         *string              `json:"email,omitempty"`
	FirstName     *string              `json:"firstName,omitempty"`
	LastName      *string              `json:"lastName,omitempty"`
	EmailVerified *bool                `json:"emailVerified,omitempty"`
	Enabled       *bool                `json:"enabled,omitempty" validate:"required"`
	Attributes    *map[string][]string `json:"attributes,omitempty"`
}

type CreateUserResponseVo struct {
	Id        *string `json:"id,omitempty"`
	Username  *string `json:"username,omitempty"`
	Email     *string `json:"email,omitempty"`
	FirstName *string `json:"firstName,omitempty"`
	LastName  *string `json:"lastName,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
}

// SetPassword handles the PUT /user/reset-password request
func SetPassword(c *gin.Context, s *service.Service) {
	var request UserVo
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	id := strings.TrimSpace(c.Param("id"))
	if request.User.ID == nil {
		request.User.ID = &id
	}

	// step 1: bind request body to struct
	err := wscutils.BindJSON(c, &request)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}
	// step 2: validate request body
	validationErrors := validate(request)

	// step 3: if there are validation errors, add them to response and send it
	if len(validationErrors) > 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}
	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeTokenMissing))
		return
	}
	// step 4: process the request
	err = client.SetPassword(c, token, id, request.Realm, *request.Password.Password, *request.Password.Temporary)
	if err != nil {
		errAry := strings.Split(err.Error(), " ")
		ermsg := strings.Join(errAry[2:], " ")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(ermsg))
		return
	}
	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse("password set successfully"))
}

// UpdateUserByID handles the PUT /user/update request
func UpdateUserByID(c *gin.Context, s *service.Service) {
	var request UserVo
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	id := strings.TrimSpace(c.Param("id"))
	if request.User.ID == nil {
		request.User.ID = &id
	}

	// step 1: bind request body to struct
	err := wscutils.BindJSON(c, &request)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}

	// step 2: validate request body
	validationErrors := validate(request)

	// step 3: if there are validation errors, add them to response and send it
	if len(validationErrors) > 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeTokenMissing))
		return
	}
	// step 4: process the request
	err = client.UpdateUser(c, token, request.Realm, request.User)
	if err != nil {
		errAry := strings.Split(err.Error(), " ")
		ermsg := strings.Join(errAry[2:], " ")
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(ermsg))
		return
	}

	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(request.User))
}

// GetUser: handles the GET /user request, this will ignore the case & return the exact match if found in case of username
func GetUser(c *gin.Context, s *service.Service) {
	lb := s.LogHarbour
	lb.Log("GetUser request received")
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	params := gocloak.GetUsersParams{}

	var user *gocloak.User
	var users []*gocloak.User
	var err error

	realm := strings.TrimSpace(c.Param("realm"))
	lb.Log(fmt.Sprintf("GetUser realm parsed: %v", map[string]any{"realm": realm}))
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeMissing))
		lb.Debug0().Log("realm null error detected")
		return
	}
	id := c.Query("id")
	userName := c.Query("name")
	if gocloak.NilOrEmpty(&id) && gocloak.NilOrEmpty(&userName) {
		id, userName = "id", "userName"
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &id), wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &userName)}))
		lb.Debug0().Log("id & name both are null")
		return
	}

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage(wscutils.ErrcodeMissing, &token)}))
		lb.LogActivity("token_missing:", err.Error)
		return
	}

	// step 4: process the request
	if !gocloak.NilOrEmpty(&id) {
		user, err = client.GetUserByID(c, token, realm, id)
		users = append(users, user)
	} else if !gocloak.NilOrEmpty(&userName) {
		params.Username = &userName
		users, err = client.GetUsers(c, token, realm, params)
	}

	user = users[0]

	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, []wscutils.ErrorMessage{wscutils.BuildErrorMessage("user_not_found", &realm)}))
		fmt.Println("ERR:", err)
		lb.Debug0().Log(fmt.Sprintf("user not found in given realm: %v", map[string]any{"error": err.Error()}))
		return
	}

	// setting response fields
	userResp := UserResponseVo{
		Id:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		EmailVerified: user.EmailVerified,
		Enabled:       user.Enabled,
		Attributes:    user.Attributes,
	}

	// step 5: if there are no errors, send success response
	lb.Log(fmt.Sprintf("User found: %v", map[string]any{"user": userResp}))
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(userResp))
}

// DeleteUserByID handles the DELETE /user/delete request
func DeleteUserByID(c *gin.Context, s *service.Service) {
	lb := s.LogHarbour
	lb.Log("DeleteUserByID request received")
	var request UserVo
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	id := strings.TrimSpace(c.Param("id"))
	lb.LogActivity("DeleteUserByID id parsed:", map[string]any{"id": id})
	if request.User.ID == nil {
		request.User.ID = &id
	}

	// step 1: bind request body to struct
	err := wscutils.BindJSON(c, &request)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		lb.Debug0().Log("realm null error detected")
		return
	}

	// step 2: validate request body
	validationErrors := validate(request)

	// step 3: if there are validation errors, add them to response and send it
	if len(validationErrors) > 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		lb.LogActivity("validation_error:", validationErrors)
		return
	}
	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeTokenMissing))
		lb.LogActivity("token_missing:", err.Error)
		return
	}
	// step 4: process the request
	err = client.DeleteUser(c, token, request.Realm, *request.User.ID)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeDatabaseError))
		lb.LogActivity(wscutils.ErrcodeDatabaseError, err.Error)
		return
	}

	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse("user_delete_successful"))
}

// FetchAllUsers handles the GET /user/list request
func FetchAllUsers(c *gin.Context, s *service.Service) {
	lb := s.LogHarbour
	lb.Log("FetchAllUsers request received")
	var request UserVo
	var usersResp []UserResponseVo
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)

	// step 1: bind request body to struct
	err := wscutils.BindJSON(c, &request)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}

	realm := c.Param("realm")
	lb.Log(fmt.Sprintf("GetUser realm parsed: %v", map[string]any{"realm": realm}))
	if gocloak.NilOrEmpty(&realm) {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeMissing))
		lb.Debug0().Log("realm null error detected")
		return
	}

	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeTokenMissing))
		return
	}

	// step 4: process the request

	users, err := client.GetUsers(c, token, realm, request.Params)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeDatabaseError))
		fmt.Println("err :", err)
		lb.LogActivity(wscutils.ErrcodeDatabaseError, err.Error)
		return
	}

	for _, eachUser := range users {
		// setting response fields
		userResp := UserResponseVo{
			Id:            eachUser.ID,
			Username:      eachUser.Username,
			Email:         eachUser.Email,
			FirstName:     eachUser.FirstName,
			LastName:      eachUser.LastName,
			EmailVerified: eachUser.EmailVerified,
			Enabled:       eachUser.Enabled,
			Attributes:    eachUser.Attributes,
		}
		usersResp = append(usersResp, userResp)
	}

	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(usersResp))
}

// CreateUser handles the POST /user request
func CreateUser(c *gin.Context, s *service.Service) {
	var request UserVo
	client := s.Dependencies["gocloak"].(*gocloak.GoCloak)
	// step 1: bind request body to struct
	err := wscutils.BindJSON(c, &request)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeInvalidJson))
		return
	}
	// step 2: validate request body
	validationErrors := validate(request)

	// step 3: if there are validation errors, add them to response and send it
	if len(validationErrors) > 0 {
		wscutils.SendErrorResponse(c, wscutils.NewResponse(wscutils.ErrorStatus, nil, validationErrors))
		return
	}
	token, err := router.ExtractToken(c.GetHeader("Authorization")) // separate "Bearer_" word from token
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse(wscutils.ErrcodeTokenMissing))
		return
	}

	// step 4: process the request
	userID, err := client.CreateUser(c, token, request.Realm, request.User)
	if err != nil {
		wscutils.SendErrorResponse(c, wscutils.NewErrorResponse("failed_to_create_user"))
		return
	}
	// save userId to user object
	request.User.ID = &userID

	// setting response fields
	userResp := CreateUserResponseVo{
		Id:        request.User.ID,
		Username:  request.User.Username,
		Email:     request.User.Email,
		FirstName: request.User.FirstName,
		LastName:  request.User.LastName,
		Enabled:   request.User.Enabled,
	}

	// step 5: if there are no errors, send success response
	wscutils.SendSuccessResponse(c, wscutils.NewSuccessResponse(userResp))
}

// validate validates the request body
func validate(userVo UserVo) []wscutils.ErrorMessage {
	// step 2.1: validate request body using standard validator
	validationErrors := wscutils.WscValidate(userVo, userVo.getValsForUserError)

	// step 2.2: add request-specific vals to validation errors
	// NOTE: it mutates validationErrors
	validationErrors = addVals(validationErrors, userVo.User)

	// if there are standard validation errors, return
	// do not execute custom validations
	if len(validationErrors) > 0 {
		return validationErrors
	}
	// step 2.3: check request specific custom validations and add errors
	validationErrors = addCustomValidationErrors(validationErrors, userVo.User)

	return validationErrors
}

// addVals adds request-specific values to a slice of ErrorMessage returned by standard validator
// This is required because vals for different requests could be different.
func addVals(validationErrors []wscutils.ErrorMessage, user gocloak.User) []wscutils.ErrorMessage {
	var nilSlice []string
	for i, err := range validationErrors {
		switch *err.Field {
		case FIRST_NAME:
			inputValue := nilSlice
			if len(err.Vals) > 0 {
				inputValue = err.Vals
			}
			validationErrors[i].Vals = inputValue
		case USER_NAME:
			inputValue := NotProvided
			validationErrors[i].Vals = []string{inputValue}
		case EMAIL_VERIFIED:
			inputValue := NotProvided
			validationErrors[i].Vals = []string{inputValue}
		case ENABLED:
			inputValue := NotProvided
			validationErrors[i].Vals = []string{inputValue}
		case USER_EMAIL:
			if err.ErrCode == RequiredError {
				inputValue := NotProvided
				validationErrors[i].Vals = []string{inputValue}
			} else if err.ErrCode == InvalidEmail {
				inputValue := user.Email
				validationErrors[i].Vals = []string{*inputValue}
			}
		}
	}
	return validationErrors
}

// addCustomValidationErrors adds custom validation errors to the validationErrors slice.
// This is required because request specific custom validators are not supported by wscvalidation.
func addCustomValidationErrors(validationErrors []wscutils.ErrorMessage, user gocloak.User) []wscutils.ErrorMessage {
	// Example of a custom validation for email domains
	if user.Email != nil && !strings.Contains(*user.Email, "@domain.com") {
		emailDomainError := wscutils.BuildErrorMessage(USER_EMAIL, user.Email)
		emailDomainError.Vals = []string{*user.Email, "@domain.com"}
		validationErrors = append(validationErrors, emailDomainError)
	}
	return validationErrors
}

// getValsForUserError returns a slice of strings to be used as vals for a validation error.
// The vals are determined based on the field and the validation rule that failed.
func (user *UserVo) getValsForUserError(err validator.FieldError) []string {
	var vals []string
	switch err.Field() {
	case PASSWORD:
		switch err.Tag() {
		case "min":
			vals = append(vals, "4")                     // Minimum valid lenght is 8
			vals = append(vals, *user.Password.Password) // provided value that failed validation
			// case "max":
			// 	vals = append(vals, "150")                  // Maximum valid age is 150
			// 	vals = append(vals, strconv.Itoa(user.Age)) // provided value that failed validation
		}
		// Add more cases as needed
	}
	return vals
}
