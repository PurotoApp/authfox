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
	"net/http"
	"time"

	"github.com/MCWertGaming/foxkit"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"gorm.io/gorm"
)

type sendVerify struct {
	UserID     string `json:"uid"`
	Token      string `json:"token"`
	VerifyCode string `json:"verify_code"`
}

func verifyUser(ctx *context.Context, pg_conn *gorm.DB, redisVerify, redisSession *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// only answer if content-type is set right
		if !foxkit.JsonRequested(c, "AuthFox") {
			return
		}

		var sendVerifyStruct sendVerify

		// put the json into the struct
		if !foxkit.BindJson(c, &sendVerifyStruct, "AuthFox") {
			return
		}

		// check if the send values are valid
		if !checkVerifyStruct(&sendVerifyStruct) {
			c.AbortWithStatus(http.StatusBadRequest)
			foxkit.LogEvent("authfox", "verifyUser(): Received invalid data")
			return
		}
		if !foxkit.CheckSession(ctx, c, &sendVerifyStruct.UserID, &sendVerifyStruct.Token, redisVerify, time.Hour*48) {
			return
		}

		// retrieve user data
		var verifyData Verify
		err := pg_conn.Where("user_id = ?", sendVerifyStruct.UserID).Take(&verifyData).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}

		// securely check if the verify token is valid
		if !foxkit.CheckToken(c, &sendVerifyStruct.VerifyCode, &verifyData.VerifyCode) {
			return
		}

		// create initial user profile
		var userProfile Profile
		userProfile.NamePretty = verifyData.NameFormat
		userProfile.NameFormat = verifyData.NameFormat
		userProfile.NameStatic = verifyData.NameStatic
		userProfile.UserID = verifyData.UserID
		userProfile.Email = verifyData.Email
		// Giving user the beta tester badge
		userProfile.BadgeBetaTester = true
		userProfile.BadgeAlphaTester = true
		userProfile.BadgeStaff = false
		// save into DB
		err = pg_conn.Create(&userProfile).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}

		// create initial user data
		var userData User
		userData.UserID = verifyData.UserID
		userData.Password = verifyData.Password
		userData.RegisterIP = verifyData.RegisterIP
		userData.RegisterTime = verifyData.RegisterTime
		// save into DB
		err = pg_conn.Create(&userData).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}

		// delete old data
		err = pg_conn.Delete(&verifyData).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}

		// delete old session
		lctx, cancel := context.WithTimeout(*ctx, time.Second*60)
		err = redisVerify.Del(lctx, sendVerifyStruct.UserID).Err()
		cancel()
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		c.Status(http.StatusAccepted)
	}
}

// returns false if the struct holds empty values
func checkVerifyStruct(verifyStruct *sendVerify) bool {
	if verifyStruct.Token == "" || verifyStruct.UserID == "" || verifyStruct.VerifyCode == "" {
		return false
	}
	return true
}
