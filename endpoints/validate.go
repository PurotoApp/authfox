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
)

type sendSession struct {
	UserID string `json:"uid"`
	Token  string `json:"token"`
}

func validateSession(ctx *context.Context, redisVerify, redisSession *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// only answer if content-type is set right
		if !foxkit.JsonRequested(c, "AuthFox") {
			return
		}
		var sendSessionStruct sendSession
		if foxkit.BindJson(c, &sendSessionStruct, "AuthFox") {
			return
		}
		if !foxkit.CheckSession(ctx, c, &sendSessionStruct.UserID, &sendSessionStruct.Token, redisSession, time.Hour*24*14) {
			return
		}
		c.Status(http.StatusOK)
	}
}