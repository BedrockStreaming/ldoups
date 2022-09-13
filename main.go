package main

import (
	"embed"
	"flag"
	"io/fs"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/BedrockStreaming/ldoups/handler"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
	// "fmt"
)

var (
	g errgroup.Group
)

//go:embed static
var embededFiles embed.FS

type config struct {
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
}

var confPath *string
var conf *config

func (c *config) loadConf() {
	yamlFile, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Printf("yamlFile.Get err #%v ", err)
		os.Exit(1)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
		os.Exit(1)
	}
	conf = c
}

type embedFileSystem struct {
	http.FileSystem
}

func (e embedFileSystem) Exists(prefix string, path string) bool {
	_, err := e.Open(path)
	return err == nil
}

func main() {
	confPath = flag.String("conf", "config.yaml", "Config path")
	flag.Parse()

	var c config
	c.loadConf()
	handler.LoadConf()
	router := gin.Default()

	staticFiles := getFileSystem(gin.Mode() != gin.ReleaseMode)
	router.Use(handler.CORS, static.Serve("/", staticFiles))
	router.NoRoute(handler.CORS, func(c *gin.Context) {
		_, file := path.Split(c.Request.RequestURI)
		ext := filepath.Ext(file)
		if file == "" || ext == "" {
			c.FileFromFS("index.html", staticFiles)
		} else {
			c.AbortWithStatus(404)
		}
	})

	router.GET("/api/login", handler.InitHandler)
	router.OPTIONS("/api/login", handler.CORS)
	router.GET("/api/users", handler.CORS, handler.InitHandler, handler.GetUsers)
	router.POST("/api/users", handler.InitHandler, handler.AddUser, handler.SetPassword)
	router.OPTIONS("/api/users", handler.CORS)
	router.GET("/api/users/:id", handler.InitHandler, handler.Get)
	router.PUT("/api/users/:id", handler.InitHandler, handler.UpdateUser, handler.SetPassword)
	router.PUT("/api/users/password", handler.InitHandler, handler.SetPassword)
	router.DELETE("/api/users/:id", handler.InitHandler, handler.Delete, handler.RemoveUser)
	router.OPTIONS("/api/users/:id", handler.CORS)
	router.GET("/api/groups", handler.InitHandler, handler.GetGroups)
	router.POST("/api/groups", handler.InitHandler, handler.AddGroup)
	router.OPTIONS("/api/groups", handler.CORS)
	router.GET("/api/groups/:id", handler.InitHandler, handler.Get)
	router.PUT("/api/groups/:id", handler.InitHandler, handler.UpdateGroup)
	router.DELETE("/api/groups/:id", handler.InitHandler, handler.Delete)
	router.OPTIONS("/api/groups/:id", handler.CORS)

	router.Run(conf.Server.Host + ":" + conf.Server.Port)

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

func getFileSystem(useOS bool) static.ServeFileSystem {
	if useOS {
		log.Print("using live mode")
		return static.LocalFile("static", false)
	}

	log.Print("using embed mode")
	fsys, err := fs.Sub(embededFiles, "static")
	if err != nil {
		panic(err)
	}

	return embedFileSystem{
		FileSystem: http.FS(fsys),
	}
}
