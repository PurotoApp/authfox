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
	"time"

	"github.com/MCWertGaming/foxkit"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"gorm.io/gorm"
)

type sendUpdateData struct {
	UserID      string `json:"uid"`
	Token       string `json:"token"`
	PasswordOld string `json:"password_old"`
	PasswordNew string `json:"password_new"`
}

func updatePassword(ctx *context.Context, pg_conn *gorm.DB, redisVerify, redisSession *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// only answer if content-type is set right
		if !foxkit.JsonRequested(c, "AuthFox") {
			return
		}

		var sendDataStruct sendUpdateData

		// put the json into the struct
		if foxkit.BindJson(c, &sendDataStruct, "AuthFox") {
			return
		}

		// validate session
		valid, err := foxkit.ValidateSession(ctx, &sendDataStruct.UserID, &sendDataStruct.Token, redisSession, time.Hour*24*14)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		} else if !valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			foxkit.LogEvent("authfox", "Received invalid session")
			return
		}

		// validate old password
		// get the hashed password
		localPass, err := findUserPassword(pg_conn, &sendDataStruct.UserID)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		// compare passwords
		if !foxkit.CheckPassword(c, &localPass, &sendDataStruct.PasswordOld) {
			return
		}

		// update password
		// TODO recycle hash
		newPassHash, err := foxkit.CreateHash(&sendDataStruct.PasswordNew)
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		// save new pass
		err = pg_conn.Model(&User{UserID: sendDataStruct.UserID}).Update("password", newPassHash).Error
		if foxkit.CheckError(c, &err, "AuthFox") {
			return
		}
		c.Status(http.StatusAccepted)
	}
}
func findUserPassword(pg_conn *gorm.DB, userID *string) (string, error) {
	var localUser User
	res := pg_conn.Where("user_id = ?", userID).Take(&localUser)
	if res.Error != nil {
		return "", res.Error
	} else if res.RowsAffected != 1 {
		return "", errors.New("invalid numbers of rows found while searching for user password")
	}
	return localUser.Password, nil
}
