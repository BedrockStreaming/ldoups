package handler

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v2"
)

type config struct {
	Ldap struct {
		BaseDN string `yaml:"baseDN"`
		RO     struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		} `yaml:"ro"`
		Url                     string            `yaml:"url"`
		UserAttributes          map[string]string `yaml:"userAttributes"`
		UsersObjectClassSearch  string            `yaml:"usersObjectClassSearch"`
		GroupAttributes         map[string]string `yaml:"groupAttributes"`
		GroupsObjectClassSearch string            `yaml:"groupsObjectClassSearch"`
	} `yaml:"ldap"`
}

type profile struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type query struct {
	Q string
}

type entry struct {
	ID         string              `json:"id"`
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
	Options    map[string]string   `json:"options"`
}

// Sorting as done here : https://pkg.go.dev/sort#example-package-SortKeys
type By func(e1, e2 *entry) bool

func (by By) Sort(entries []entry) {
	es := &entrySorter{
		entries: entries,
		by:      by,
	}
	sort.Sort(es)
}

type entrySorter struct {
	entries []entry
	by      func(e1, e2 *entry) bool // Closure used in the Less method.
}

func (s *entrySorter) Len() int {
	return len(s.entries)
}

func (s *entrySorter) Swap(i, j int) {
	s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
}

func (s *entrySorter) Less(i, j int) bool {
	return s.by(&s.entries[i], &s.entries[j])
}

var displayName = func(e1, e2 *entry) bool {
	return e1.Attributes["displayName"][0] < e2.Attributes["displayName"][0]
}

var dn = func(e1, e2 *entry) bool {
	return e1.DN < e2.DN
}

var reverseDisplayName = func(e1, e2 *entry) bool {
	return displayName(e2, e1)
}

var reverseDn = func(e1, e2 *entry) bool {
	return dn(e2, e1)
}

func prepareEntries(entriesL []*ldap.Entry) []entry {
	var entries []entry
	for _, ent := range entriesL {
		var entry entry
		entry.ID = ent.DN
		entry.DN = ent.DN
		entry.Attributes = make(map[string][]string)
		for _, at := range ent.Attributes {
			entry.Attributes[at.Name] = at.Values
		}
		entries = append(entries, entry)
	}
	return entries
}

var conf *config

func (c *config) loadConf() {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	conf = c
}

func LoadConf() {
	var c config
	c.loadConf()
}

type errorMessage struct {
	Message string            `json:"message"`
	Status  int               `json:"status"`
	Errors  map[string]string `json:"errors"`
}

func abort(c *gin.Context, err error, statusCode int) {
	log.Print(err)
	var errorM errorMessage
	errorM.Message = fmt.Sprintf("%s", err)
	errorM.Status = statusCode
	errorM.Errors = make(map[string]string)
	c.JSON(statusCode, errorM)
}

func Delete(c *gin.Context) {
	l, ok := c.Get("LDAP")
	if !ok {
		abort(c, errors.New("can't get ldap conn"), http.StatusInternalServerError)
		return
	}
	ldp, ok := l.(*ldap.Conn)
	if !ok {
		abort(c, errors.New("can't get ldap conn"), http.StatusInternalServerError)
		return
	}

	id := c.Param("id")
	delReq := ldap.NewDelRequest(id, []ldap.Control{})

	if err := ldp.Del(delReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
}

func Get(c *gin.Context) {
	l, ok := c.Get("LDAP")
	if !ok {
		abort(c, errors.New("can't get ldap conn"), http.StatusInternalServerError)
		return
	}
	ldp, ok := l.(*ldap.Conn)
	if !ok {
		abort(c, errors.New("can't get ldap Conn"), http.StatusInternalServerError)
		return
	}

	id := c.Param("id")
	attr := c.QueryArray("attr")
	// rnge := c.QueryArray("range")
	// flter := c.QueryArray("filter")

	filter := "(objectClass=*)"
	searchReq := ldap.NewSearchRequest(id, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, attr, []ldap.Control{})

	result, err := ldp.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
	c.Header("Access-Control-Expose-Headers", "*")
	c.Header("Content-Range", "posts *")

	entries := prepareEntries(result.Entries)

	// Search for member of user
	if strings.HasPrefix(c.Request.URL.Path, "/api/users/cn=") {
		getGroups(c, &entries[0])
	}

	c.JSON(http.StatusOK, entries[0])

}

// https://cybernetist.com/2020/05/18/getting-started-with-go-ldap/
func connect(c *gin.Context) *ldap.Conn {
	l, err := ldap.DialURL(conf.Ldap.Url)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return nil
	}
	return l
}

func Login(l *ldap.Conn, c *gin.Context) bool {
	username, password, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		c.Header("WWW-Authenticate", "Basic realm=Restricted")
		abort(c, errors.New("Unauthenticated"), http.StatusUnauthorized)
		return false
	}

	userDN, userMail := findUserDNAndMail(l, c, username)
	if userDN == "" {
		return false
	}

	err := l.Bind(userDN, password)
	if err != nil {
		c.Header("WWW-Authenticate", "Basic realm=Restricted")
		abort(c, err, http.StatusUnauthorized)
		return false
	}
	c.Header("Access-Control-Allow-Origin", "*")
	if c.FullPath() == "/api/login" {
		var profile profile
		profile.Username = username
		profile.Email = userMail
		c.JSON(http.StatusOK, profile)
	}
	return true
}

func findUserDNAndMail(l *ldap.Conn, c *gin.Context, username string) (string, string) {
	err := l.Bind(conf.Ldap.RO.Username, conf.Ldap.RO.Password)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return "", ""
	}
	filter := ""
	filter = "(&(objectClass=" + conf.Ldap.UsersObjectClassSearch + ")(cn=" + username + "))"

	searchReq := ldap.NewSearchRequest(conf.Ldap.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"dn", "mail"}, []ldap.Control{})

	result, err := l.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return "", ""
	}

	if len(result.Entries) > 1 {
		abort(c, errors.New("username isn't unique, please contact administrator"), http.StatusConflict)
	}

	if len(result.Entries) == 0 {
		return "cn=" + username + "," + conf.Ldap.BaseDN, ""
	}

	return result.Entries[0].DN, result.Entries[0].Attributes[0].Values[0]
}

func CORS(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "*")
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Expose-Headers", "*")
}

func InitHandler(c *gin.Context) {
	l := connect(c)
	if l != nil && Login(l, c) {
		c.Set("LDAP", l)
	}

	c.Next()
	l.Close()
}
