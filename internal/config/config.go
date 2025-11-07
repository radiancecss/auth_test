package config

type Config struct {
	ServerPort        string
	JWTSecret         string
	TokenLifetimeMins int
}
