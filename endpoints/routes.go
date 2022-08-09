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

	"github.com/MCWertGaming/foxkit"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v9"
	"gorm.io/gorm"
)

func SetRoutes(ctx *context.Context, router *gin.Engine, pg_conn *gorm.DB, redisVerify, redisSession *redis.Client) {
	router.POST("/v1/user", registerUser(ctx, pg_conn, redisVerify, redisSession))
	router.POST("/v1/user/login", loginUser(ctx, pg_conn, redisVerify, redisSession))
	router.POST("/v1/user/verify", verifyUser(ctx, pg_conn, redisVerify, redisSession))
	router.POST("/v1/user/validate", validateSession(ctx, redisVerify, redisSession))
	router.PATCH("/v1/user", updatePassword(ctx, pg_conn, redisVerify, redisSession))
	// router.POST("/v1/user/delete", accountDeletion(collVerifySession, collSession, collUsers, collProfiles))
	// swagger docs
	router.Static("/swagger", "swagger/")
	// user redirects
	router.GET("/", foxkit.Redirect("/swagger"))
	router.GET("/v1", foxkit.Redirect("/swagger"))
}
