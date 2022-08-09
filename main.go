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

package main

import (
	"context"

	"github.com/MCWertGaming/foxkit"
	"github.com/PurotoApp/authfox/endpoints"
	"github.com/gin-gonic/gin"
)

func main() {
	// connect to the PostgreSQL
	pg_conn := foxkit.ConnectSQL()

	// create context
	ctx := context.Background()

	// Connect to Redis and test connection
	redisVerify := foxkit.ConnectRedis(ctx, 1)
	redisSession := foxkit.ConnectRedis(ctx, 2)

	// migrate all tables
	foxkit.AutoMigrateSQL(pg_conn, &endpoints.Verify{}, &endpoints.User{}, &endpoints.Profile{})

	// create router
	router := gin.Default()

	// configure gin
	// TODO: add proxy URL in production
	foxkit.ConfigRouter(router, nil)

	// set routes
	endpoints.SetRoutes(&ctx, router, pg_conn, redisVerify, redisSession)

	// start
	foxkit.StartRouter(router, "0.0.0.0:4444")

	// clean up
	redisVerify.Close()
	redisSession.Close()
}
