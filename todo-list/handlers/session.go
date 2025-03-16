package handlers

import (
	"net/http"
	"todo-list/database"
	"todo-list/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("your-secret-key")) // Secure key for session

// LoginUserWithSession: check session exists earlier and Create a session when a user logs in
func LoginUserWithSession(c *gin.Context) {
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the user credentials
	var storedUser models.User
	err := database.DB.QueryRow("SELECT name, email, password FROM users WHERE email = ?", user.Email).Scan(&storedUser.Name, &storedUser.Email, &storedUser.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or user not found"})
		return
	}

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// Check if a session already exists after validating credentials
	session, _ := store.Get(c.Request, "session-name")
	if session.Values["userID"] == storedUser.Email {
		c.JSON(http.StatusOK, gin.H{"message": "You are already logged in"})
		return
	}

	// Create a session for the user
	session.Values["userID"] = storedUser.Email
	session.Save(c.Request, c.Writer)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// LogoutUser: Destroy the session
func LogoutUser(c *gin.Context) {
	session, _ := store.Get(c.Request, "session-name")
	session.Options.MaxAge = -1 // Destroy session
	session.Save(c.Request, c.Writer)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}
