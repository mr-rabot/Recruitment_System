package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"xorm.io/xorm"
)

var (
	jwtSecret = []byte("123456789")
	engine    *xorm.Engine
	db        *gorm.DB
)

type Claims struct {
	UserID   int64  `json:"user_id"`
	UserType string `json:"user_type"`
	jwt.StandardClaims
}

type User struct {
	ID           int64  `xorm:"pk autoincr" json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	UserType     string `json:"user_type"`
}

type Profile struct {
	ID          int64  `xorm:"pk autoincr" json:"id"`
	ApplicantID int64  `json:"applicant_id"`
	ResumeFile  string `json:"resume_file"`
	Skills      string `json:"skills"`
	Education   string `json:"education"`
	Experience  string `json:"experience"`
	Phone       string `json:"phone"`
}

type Job struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	PostedBy         uint      `json:"posted_by"`
	PostedOn         time.Time `json:"posted_on"`
	TotalApplications int      `json:"total_applications"`
}

type Application struct {
	ID     uint `gorm:"primaryKey" json:"id"`
	UserID uint `json:"user_id"`
	JobID  uint `json:"job_id"`
}

func InitDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	engine, err = xorm.NewEngine("sqlite3", "test.db")
	if err != nil {
		panic(err)
	}

	err = db.AutoMigrate(&User{}, &Profile{}, &Job{}, &Application{})
	if err != nil {
		panic(err)
	}
}

func main() {
	InitDB()
	r := gin.Default()
	r.Use(cors.Default())

	// User routes
	r.POST("/signup", SignUp)
	r.POST("/login", Login)

	// Applicant routes
	applicant := r.Group("/applicant")
	{
		applicant.POST("/uploadResume", AuthMiddleware("Applicant"), UploadResume)
		applicant.GET("/jobs", AuthMiddleware("Applicant"), ViewJobs)
		applicant.POST("/jobs/apply", AuthMiddleware("Applicant"), ApplyJob)
	}

	// Admin routes
	admin := r.Group("/admin")
	{
		admin.POST("/job", AuthMiddleware("Admin"), CreateJob)
		admin.GET("/job/:job_id", AuthMiddleware("Admin"), ViewJob)
		admin.GET("/applicants", AuthMiddleware("Admin"), ListApplicants)
		admin.GET("/applicant/:applicant_id", AuthMiddleware("Admin"), ViewApplicant)
	}

	fmt.Printf("Server started. ... ")
	r.Run(":8080")
}

func SignUp(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password encryption failed"})
		return
	}

	user.PasswordHash = string(hash)
	_, err = engine.Insert(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User registration failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	has, err := engine.Where("email = ?", req.Email).Get(&user)
	if err != nil || !has || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	claims := &Claims{
		UserID:   user.ID,
		UserType: user.UserType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func AuthMiddleware(userType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid || claims.UserType != userType {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or unauthorized token"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

func UploadResume(c *gin.Context) {
	userID := c.GetInt64("userID")

	file, _, err := c.Request.FormFile("resume")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to upload file"})
		return
	}
	defer file.Close()

	buffer := new(bytes.Buffer)
	_, err = io.Copy(buffer, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	req, err := http.NewRequest("POST", "https://api.apilayer.com/resume_parser/upload", buffer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("apikey", "gNiXyflsFu3WNYCz1ZCxdWDb7oQg1Nl1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process resume"})
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	var parsedData map[string]interface{}
	if err := json.Unmarshal(body, &parsedData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	var profile Profile
	profile.ApplicantID = userID
	profile.ResumeFile = "path/to/your/uploaded/file"
	profile.Skills = extractData(parsedData["skills"])
	profile.Education = extractData(parsedData["education"])
	profile.Experience = extractData(parsedData["experience"])
	profile.Phone = parsedData["phone"].(string)

	_, err = engine.Insert(&profile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Resume uploaded successfully", "profile": profile})
}

func CreateJob(c *gin.Context) {
	var job Job
	if err := c.ShouldBindJSON(&job); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	job.PostedOn = time.Now()
	if err := db.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, job)
}

func ViewJob(c *gin.Context) {
	jobID, err := strconv.Atoi(c.Param("job_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	var job Job
	if err := db.First(&job, jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	c.JSON(http.StatusOK, job)
}

func ListApplicants(c *gin.Context) {
	var applicants []Profile
	if err := engine.Find(&applicants); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, applicants)
}

func ViewApplicant(c *gin.Context) {
	applicantID, err := strconv.Atoi(c.Param("applicant_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid applicant ID"})
		return
	}

	var profile Profile
	has, err := engine.ID(applicantID).Get(&profile)
	if err != nil || !has {
		c.JSON(http.StatusNotFound, gin.H{"error": "Applicant not found"})
		return
	}

	c.JSON(http.StatusOK, profile)
}

func ViewJobs(c *gin.Context) {
	var jobs []Job
	if err := db.Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, jobs)
}

func ApplyJob(c *gin.Context) {
	userID := c.GetInt64("userID")

	var application Application
	if err := c.ShouldBindJSON(&application); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	application.UserID = uint(userID)
	if err := db.Create(&application).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, application)
}

func extractData(data interface{}) string {
	if data == nil {
		return ""
	}

	switch v := data.(type) {
	case []interface{}:
		strs := make([]string, len(v))
		for i, val := range v {
			strs[i] = fmt.Sprintf("%v", val)
		}
		return strings.Join(strs, ", ")
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
