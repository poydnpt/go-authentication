package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	client, ctx, cancel, err := connectMongo("mongodb://localhost:27017")
	if err != nil {
		panic(err)
	}
	fmt.Println("Connect Mongo Successfully..")

	defer closeMongo(client, ctx, cancel)

	clientRedis := connectRedis()
	pong, errRedis := clientRedis.Ping().Result()
	fmt.Println(pong, errRedis)
	fmt.Println("Connect Redis Successfully..")

	// insert user data
	// insertUsers(client, ctx)

	// list all users
	// getAllUsers(client, ctx)

	handler := newHandler(client, ctx, clientRedis)

	r := gin.New()

	r.POST("/login", handler.loginHandler)
	r.GET("/validateToken", validateHandler)
	r.POST("/logout", handler.logoutHandler)

	r.Run()
}

type Handler struct {
	client      *mongo.Client
	ctx         context.Context
	clientRedis *redis.Client
}

func newHandler(client *mongo.Client, ctx context.Context, clientRedis *redis.Client) *Handler {
	return &Handler{client, ctx, clientRedis}
}

func (h *Handler) loginHandler(c *gin.Context) {
	var username = "test001"
	// var password = "P@ssw0rd"
	password := []byte("P@ssw0rd")

	//Get token from Redis in case of user is still login
	val, e := h.clientRedis.Get(username).Result()
	if e != nil {
		fmt.Println(e)
	}

	fmt.Println("******* ", val)
	fmt.Println("******* ", len(val))
	if len(val) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"access_token": val,
		})
		fmt.Println("Token from redis")
		return
	}

	result := findUserByUsername(h.client, h.ctx, username)

	// Hashing the password with the default cost of 10
	// hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	// if err != nil {
	// 	panic(err)
	// }
	// err = bcrypt.CompareHashAndPassword(hashedPassword, test)

	// Comparing the password with the hash
	err := bcrypt.CompareHashAndPassword([]byte(result.PASSWORD), password)
	fmt.Println(err) // nil means it is a match

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	fmt.Println("Login Successfully..")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	})

	ss, err := token.SignedString([]byte("MySignatureTest"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}

	//Save token into Redis
	err = h.clientRedis.Set(username, ss, 0).Err()
	if err != nil {
		panic(err)
	}
	fmt.Println("Already add token to Redis for username: ", username)

	c.JSON(http.StatusOK, gin.H{
		"access_token": ss,
	})
}

func validateHandler(c *gin.Context) {
	s := c.Request.Header.Get("Authorization")

	token := strings.TrimPrefix(s, "Bearer ")

	if err := validateToken(token); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		c.JSON(http.StatusUnauthorized, "status: Invalid Token")
		return
	}

	c.JSON(http.StatusOK, "status: Valid Token")
}

func validateToken(token string) error {
	_, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte("MySignatureTest"), nil
	})

	return err
}

func (h *Handler) logoutHandler(c *gin.Context) {
	var username = "test001"

	val, err := h.clientRedis.Del(username).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Remove token from redis:  ", val)
	c.JSON(http.StatusOK, "Logout Successfully")
}

func connectMongo(uri string) (*mongo.Client, context.Context, context.CancelFunc, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		30*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	return client, ctx, cancel, err
}

func closeMongo(client *mongo.Client, ctx context.Context,
	cancel context.CancelFunc) {

	defer cancel()

	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()
}

func connectRedis() (clientRedis *redis.Client) {

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	return client
}

func findUserByUsername(client *mongo.Client, ctx context.Context, username string) (results User) {
	var result User
	collection := client.Database("user").Collection("users")
	filter := bson.D{{"username", username}}
	err := collection.FindOne(ctx, filter).Decode(&result)

	if err != nil {
		panic(err)
	}
	return result
}

// Insert user data
func insertUsers(client *mongo.Client, ctx context.Context) {
	collection := client.Database("user").Collection("users")

	var documents = []interface{}{
		bson.D{
			{"username", "test101"},
			{"no", "101"},
			{"email", "test@test.com"},
			{"password", "2e763f0fe93cfa633039db0352e229632b207bb768bddf40efdaf67dd5440661dd8735f364b675be"},
			{"role", "admin"},
		},
		bson.D{
			{"username", "test102"},
			{"no", "102"},
			{"email", "test@test.com"},
			{"password", "2e763f0fe93cfa633039db0352e229632b207bb768bddf40efdaf67dd5440661dd8735f364b675be"},
			{"role", "admin"},
		},
	}
	result, err := collection.InsertMany(ctx, documents)

	if err != nil {
		panic(err)
	}

	fmt.Println("Result of InsertMany")
	for id := range result.InsertedIDs {
		fmt.Println(id)
	}
	return
}

// Get list of user
func getAllUsers(client *mongo.Client, ctx context.Context) {
	collection := client.Database("user").Collection("users")
	cursor, err := collection.Find(ctx, bson.D{{}}, options.Find())

	if err != nil {
		panic(err)
	}

	var results []bson.D
	if err := cursor.All(ctx, &results); err != nil {
		panic(err)
	}

	fmt.Println("List all users")
	for _, doc := range results {
		fmt.Println(doc)
	}
}

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	USERNAME string             `bson:"username"`
	PASSWORD string             `bson:"password"`
	NO       string             `bson:"no"`
	EMAIL    string             `bson:"email"`
	ROLE     string             `bson:"role"`
}
