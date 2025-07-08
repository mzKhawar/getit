package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"log"
	"net/http"
	"strconv"
)

type ApiServer struct {
	listenAddr string
	service    Service
}

func NewApiServer(listenAddr string, service Service) *ApiServer {
	return &ApiServer{listenAddr: listenAddr, service: service}
}

func (s *ApiServer) Run() {
	router := gin.Default()
	protected := router.Group("", s.JwtMiddleware)
	{
		users := protected.Group("/users")
		users.GET("/", s.HandleGetUsers)
		users.GET("/:userId", s.RequireUserMatch, s.HandleGetUserById)
		users.PATCH("/:userId", s.RequireUserMatch, s.HandleUpdateEmail)
		users.DELETE("/:userId", s.RequireUserMatch, s.HandleDeleteUser)
	}
	{
		auth := router.Group("/auth")
		auth.POST("/register", s.HandleRegister)
		auth.POST("/authenticate", s.HandleAuthenticate)

	}
	if err := router.Run(s.listenAddr); err != nil {
		log.Fatalf("error running server: %v", err)
	}
}

func (s *ApiServer) HandleGetUsers(c *gin.Context) {
	users, err := s.service.GetUsers(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (s *ApiServer) HandleGetUserById(c *gin.Context) {
	idStr := c.Param("userId")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	usr, err := s.service.GetUserById(c, id)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, usr)
}

func (s *ApiServer) HandleUpdateEmail(c *gin.Context) {
	idStr := c.Param("userId")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var emailRequest UpdateEmailRequest
	if err := c.ShouldBindJSON(&emailRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.service.UpdateEmail(c, id, emailRequest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	c.Status(http.StatusNoContent)
}

func (s *ApiServer) HandleDeleteUser(c *gin.Context) {
	idStr := c.Param("userId")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.service.DeleteUser(c, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *ApiServer) HandleRegister(c *gin.Context) {
	var registerReq RegisterRequest
	if err := c.ShouldBindJSON(&registerReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	usrResponse, jwt, err := s.service.Register(c, registerReq)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	location := fmt.Sprintf("users/%d", usrResponse.Id)
	c.Header("Location", location)
	c.JSON(http.StatusCreated, gin.H{"jwt": jwt})
}

func (s *ApiServer) HandleAuthenticate(c *gin.Context) {
	var authRequest AuthenticationRequest
	if err := c.ShouldBindJSON(&authRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	jwt, err := s.service.Authenticate(c, authRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"jwt": jwt})
}

// TODO: need to check if jwt user is the same
func (s *ApiServer) JwtMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || authHeader[:7] != "Bearer " {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	jwt := authHeader[7:]
	token, err := s.service.ValidateJwt(jwt)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	user, err := s.service.GetUserFromValidJwt(c, token)
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Set("uId", user.Id)
	c.Next()
}

func (s *ApiServer) RequireUserMatch(c *gin.Context) {
	uIDFromToken := c.GetInt("uId")
	paramId, err := strconv.Atoi(c.Param("userId"))
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	if uIDFromToken != paramId {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}
