package main

import (
	"github.com/PurotoApp/authfox/internal/endpoints"
	"github.com/PurotoApp/authfox/internal/ginHelper"
	"github.com/PurotoApp/authfox/internal/logHelper"
	"github.com/PurotoApp/authfox/internal/mongoHelper"
	"github.com/gin-gonic/gin"
)

func main() {
	// create DB connection
	client, err := mongoHelper.ConnectDB(mongoHelper.GetDBUri())
	loghelper.ErrorFatal("MongoDB", err)
	// create collections
	collUsers := client.Database("authfox").Collection("users")
	collVerify := client.Database("authfox").Collection("verify")
	collSession := client.Database("authfox").Collection("session")
	collVerifySession := client.Database("authfox").Collection("verifySession")
	collProfiles := client.Database("authfox").Collection("profiles")

	// test the connection
	loghelper.ErrorFatal("MongoDB", mongoHelper.TestDBConnection(client))
	// close connection on program exit
	defer func() {
		loghelper.ErrorFatal("MongoDB", mongoHelper.DisconnectDB(client))
	}()

	// set up gin
	ginHelper.SwitchRelMode()

	// create router
	router := gin.Default()

	// configure gin
	ginHelper.ConfigRouter(router)

	// set routes
	endpoints.SetRoutes(router, collUsers, collVerify, collSession, collVerifySession, collProfiles)

	// start
	router.Run("localhost:3621")

	// close DB connection
	defer logHelper.ErrorFatal(mongoHelper.DisconnectDB(client))
}
