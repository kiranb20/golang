package main

import (
	"log"
	"todo-list/database" // Import the database package
	"todo-list/handlers" // Import the handlers package

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize the database connection
	database.InitDB()
	defer database.DB.Close() // Close the database connection when the app exits

	// Create a new Gin router
	r := gin.Default()

	log.Println("it came to route")
	// Register routes
	r.POST("/register", handlers.RegisterUser)
	r.POST("/login", handlers.LoginUserWithSession)
	r.POST("/logout", handlers.LogoutUser) // New logout route
	// r.GET("/session-check", handlers.CheckSession) // Session validation route

	// Start the server
	r.Run(":8080") // Runs the server on http://localhost:8080
}
