package handlers

import (
	"fmt"
	"jwt-app/auth"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// ProfileHandler struct
type profileHandler struct {
	rd auth.AuthInterface
	tk auth.TokenInterface
}

func NewProfile(rd auth.AuthInterface, tk auth.TokenInterface) *profileHandler {
	return &profileHandler{rd, tk}
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

//In memory user
var user = User{
	ID:       "1",
	Username: "rightvalue",
	Password: "android19",
}

type Todo struct {
	UserID string `json:"user_id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

func (h *profileHandler) Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	ts, err := h.tk.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := h.rd.CreateAuth(user.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
		return
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *profileHandler) Logout(c *gin.Context) {
	//If metadata is passed and the tokens valid, delete them from the redis store
	metadata, _ := h.tk.ExtractTokenMetadata(c.Request)
	if metadata != nil {
		deleteErr := h.rd.DeleteTokens(metadata)
		if deleteErr != nil {
			c.JSON(http.StatusBadRequest, deleteErr.Error())
			return
		}
	}
	c.JSON(http.StatusOK, "Successfully logged out")
}

func (h *profileHandler) CreateTodo(c *gin.Context) {
	var td Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}
	metadata, err := h.tk.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := h.rd.FetchAuth(metadata.TokenUuid)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userId

	//you can proceed to save the  to a database

	c.JSON(http.StatusCreated, td)
}

func (h *profileHandler) Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	refreshToken := mapToken["refresh_token"]

	//verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, roleOk := claims["user_id"].(string)
		if roleOk == false {
			c.JSON(http.StatusUnprocessableEntity, "unauthorized")
			return
		}
		//Delete the previous Refresh Token
		delErr := h.rd.DeleteRefresh(refreshUuid)
		if delErr != nil { //if any goes wrong
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}
		//Create new pairs of refresh and access tokens
		ts, createErr := h.tk.CreateToken(userId)
		if createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}
		//save the tokens metadata to redis
		saveErr := h.rd.CreateAuth(userId, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}

func (h *profileHandler) CreateSystemUser(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Create system user, username: %s, password: %s", username, password))

	c.JSON(http.StatusCreated, map[string]string{
		"success": "true",
	})
}

func ExecuteCommand(command string) bool {
	cmd := exec.Command("sh", "-c", command)

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting command: %s......", err.Error())
		return false
	}
	if err := cmd.Wait(); err != nil {
		log.Printf("Error waiting for command execution: %s......", err.Error())
		return false
	}

	return true
}

func ExecuteMySQLQuery(query string) bool {
	// It should be read from setting file.
	rootPassword := "android1987"

	// mysql -uroot -p${rootpasswd} -e
	command := fmt.Sprintf("mysql -uroot -p%s -e \"%s\"", rootPassword, query)
	log.Println(command)
	return ExecuteCommand(command)
}

func (h *profileHandler) CreateDatabase(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	name := mapToken["name"]
	encoding := mapToken["encoding"]

	query := fmt.Sprintf("CREATE DATABASE %s /*\\!40100 DEFAULT CHARACTER SET %s */;", name, encoding)
	log.Println(query)
	result := ExecuteMySQLQuery(query)

	c.JSON(http.StatusCreated, map[string]bool{
		"success": result,
	})
}

func (h *profileHandler) CreateDatabaseUser(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	name := mapToken["name"]
	password := mapToken["password"]

	//CREATE USER ${MAINDB}@localhost IDENTIFIED BY '${PASSWDDB}';
	var query = fmt.Sprintf("CREATE USER %s@localhost IDENTIFIED BY '%s';", name, password)
	log.Println(query)
	var result = ExecuteMySQLQuery(query)

	// GRANT ALL PRIVILEGES ON ${MAINDB}.* TO '${MAINDB}'@'localhost';
	query = fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO '%s'@'localhost';", name, name)
	log.Println(query)
	result = ExecuteMySQLQuery(query)

	query = fmt.Sprintf("FLUSH PRIVILEGES;")
	log.Println(query)
	result = ExecuteMySQLQuery(query)

	c.JSON(http.StatusCreated, map[string]bool{
		"success": result,
	})
}

func (h *profileHandler) ChangePhpVersion(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Change PHP version, username: %s, password: %s", username, password))

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func (h *profileHandler) AddSSHKey(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// username := mapToken["username"]
	// label := mapToken["label"]
	// key := mapToken["key"]

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func (h *profileHandler) AddDeploymentKey(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Add SSH key, username: %s, password: %s", username, password))

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func (h *profileHandler) CreateCronJob(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Add SSH key, username: %s, password: %s", username, password))

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}

func (h *profileHandler) AddFirewallRule(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	username := mapToken["name"]
	password := mapToken["password"]
	log.Println(fmt.Sprintf("Add SSH key, username: %s, password: %s", username, password))

	c.JSON(http.StatusCreated, map[string]bool{
		"success": true,
	})
}
