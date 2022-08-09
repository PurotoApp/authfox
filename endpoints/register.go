/* <AuthFox - a simple authentication and session server for Puroto>
   Copyright (C) 2022  PurotoApp

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package endpoints

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/MCWertGaming/foxkit"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"gorm.io/gorm"
)

// This struct stores user information send to the register API endpoint
type sendUserProfile struct {
	// the send user name
	NameFormat string `json:"user_name"`
	// Plain-text password received from client
	Password string `json:"password"`
	// account email
	Email string `json:"email"`
}

// This is like sessionPair but without the session type switch
type returnSession struct {
	UserID string `json:"uid"`
	Token  string `json:"token"`
}

func registerUser(ctx *context.Context, pg_conn *gorm.DB, redisVerify, redisSession *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// only answer if content-type is set right
		if !foxkit.JsonRequested(c, "authfox") {
			return
		}

		var sendUserStruct sendUserProfile

		// put the json into the struct
		if !foxkit.BindJson(c, &sendUserStruct, "AuthFox") {
			return
		}

		// make sure that the received values are legal
		if !checkSendUserProfile(&sendUserStruct) {
			c.AbortWithStatus(http.StatusBadRequest)
			foxkit.LogEvent("authfox", "registerUser(): Received invalid or illegal registration data")
			return
		}

		// check if the given email or user name already exists
		result := pg_conn.Where("name_static = ?", strings.ToLower(sendUserStruct.NameFormat)).Where("email = ?", strings.ToLower(sendUserStruct.Email)).Take(&Verify{})
		if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.AbortWithStatus(http.StatusInternalServerError)
			foxkit.LogError("authfox", result.Error)
			return
		} else if result.RowsAffected > 0 {
			c.AbortWithStatus(http.StatusBadRequest)
			foxkit.LogEvent("authfox", "Received user that already exists")
			return
		}

		// prepare saving of user data into verify DB
		var userData Verify

		// hash the password
		hash, err := foxkit.CreateHash(&sendUserStruct.Password)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		// safe the hashed password
		userData.Password = hash
		// remove the old password from memory
		sendUserStruct.Password = ""

		// fill other user data
		userData.NameFormat = sendUserStruct.NameFormat
		userData.NameStatic = strings.ToLower(sendUserStruct.NameFormat)
		userData.Email = strings.ToLower(sendUserStruct.Email)
		userData.RegisterIP = c.ClientIP()
		userData.RegisterTime = time.Now()
		userData.VerifyCode, err = foxkit.RandomString(32)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		// create user ID
		userData.UserID = foxkit.GetUUID()

		// store into DB
		err = pg_conn.Create(&userData).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}

		// create session
		sessionID, sessionKey, err := foxkit.CreateSession(ctx, &userData.UserID, redisVerify, 512, 1, time.Hour*48)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		c.JSON(http.StatusAccepted, returnSession{sessionID, sessionKey})
	}
}

// check the send user data for correctness and forbidden values
func checkSendUserProfile(profile *sendUserProfile) bool {
	// TODO: refuse if the name contains slurs / forbidden words
	if !foxkit.CheckString(profile.NameFormat, 6, 32, true) {
		return false
	}
	// TODO: refuse if the email address is forbidden (trashmail etc)
	if !foxkit.CheckEmail(profile.Email) {
		return false
	}
	// TODO: refuse on weak passwords like "password", must be checked before hashing
	if !foxkit.CheckString(profile.Password, 9, 512, true) {
		return false
	}
	return true
}
