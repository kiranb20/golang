package handlers

import (
	"log"
	"net/http"
	"strings"
	"todo-list/database"
	"todo-list/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Secure key for session cookies
var store = sessions.NewCookieStore([]byte("test@123")) // Secure key for session

// SanitizeSessionName ensures session names are valid cookie names
func sanitizeSessionName(email string) string {
	// Replace special characters like @ and . in the email with underscores
	return "session-" + strings.ReplaceAll(strings.ReplaceAll(email, "@", "_"), ".", "_")
}

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

	// Generate a sanitized session name
	sessionName := sanitizeSessionName(storedUser.Email)
	session, _ := store.Get(c.Request, sessionName)

	// Check if a session already exists after validating credentials
	// session, _ = store.Get(c.Request, "session-name")
	if session.Values["userID"] == storedUser.Email {
		log.Printf("Session already active for user: %s", storedUser.Email)
		c.JSON(http.StatusOK, gin.H{"message": "You are already logged in"})
		return
	}

	// Create a new session for the user
	session.Values["userID"] = storedUser.Email
	session.Save(c.Request, c.Writer)
	log.Printf("New session created for user: %s", storedUser.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// LogoutUser: Destroys the session associated with the user
func LogoutUser(c *gin.Context) {
	// Assume the email is sent in the request to identify the session
	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate a sanitized session name
	sessionName := sanitizeSessionName(user.Email)
	session, err := store.Get(c.Request, sessionName)

	if err != nil {
		log.Printf("Error fetching session for user: %s, error: %v", user.Email, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active session found"})
		return
	}

	// Check if the session exists
	if session.Values["userID"] == nil {
		log.Printf("No active session found for user: %s", user.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active session found"})
		return
	}

	// Destroy the session
	session.Options.MaxAge = -1 // Invalidate the session
	err = session.Save(c.Request, c.Writer)
	if err != nil {
		log.Printf("Error destroying session for user: %s, error: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not log out"})
		return
	}

	log.Printf("Session destroyed for user: %s", user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}
