package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func GetGroups(c *gin.Context) {
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

	attr := c.QueryArray("attr")
	rnge := c.QueryArray("range")
	srt := c.QueryArray("sort")
	flter := c.QueryArray("filter")

	var query query
	if len(flter) > 0 {
		json.Unmarshal([]byte(flter[0]), &query)
	}

	filter := ""
	if query.Q != "" {
		filter = "(&(objectClass=" + conf.Ldap.GroupsObjectClassSearch + ")(cn=*" + query.Q + "*))"
	} else {
		filter = "(&(objectClass=" + conf.Ldap.GroupsObjectClassSearch + "))"
	}

	searchReq := ldap.NewSearchRequest(conf.Ldap.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, attr, []ldap.Control{})

	result, err := ldp.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
	c.Header("Access-Control-Expose-Headers", "*")

	start := 0
	end := 0
	if len(rnge) > 0 {
		split := strings.Split(rnge[0], ",")
		start, _ = strconv.Atoi(split[0][1:])
		end, _ = strconv.Atoi(split[1][:len(split[1])-1])
		if end > len(result.Entries) {
			end = len(result.Entries)
		}
	} else {
		start = 0
		end = len(result.Entries)
	}

	c.Header("Content-Range", fmt.Sprintf("posts %d-%d/%d", start, end, len(result.Entries)))

	if len(result.Entries) > 0 {
		entries := prepareEntries(result.Entries)

		if len(srt) > 0 {
			var attr string
			var order string
			fmt.Sscanf(srt[0], `["%s","%s"]`, &attr, &order)
			switch order {
			case "ASC":
				if attr == "dn" {
					By(dn).Sort(entries)
				}
			case "DESC":
				if attr == "dn" {
					By(reverseDn).Sort(entries)
				}
			}
		}

		c.JSON(http.StatusOK, entries[start:end])
	} else {
		c.JSON(http.StatusOK, make([]string, 0))
	}
}

func UpdateGroup(c *gin.Context) {
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

	var group entry
	if err := c.BindJSON(&group); err != nil {
		abort(c, err, http.StatusBadRequest)
		return
	}

	modReq := ldap.NewModifyRequest(group.DN, []ldap.Control{})
	for attr, _ := range conf.Ldap.GroupAttributes {
		if val, ok := group.Attributes[attr]; ok {
			modReq.Replace(attr, val)
		}
	}

	if err := ldp.Modify(modReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
}

func AddGroup(c *gin.Context) {
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

	var group entry
	if err := c.BindJSON(&group); err != nil {
		abort(c, err, http.StatusBadRequest)
		return
	}

	addReq := ldap.NewAddRequest(group.DN, []ldap.Control{})
	for attr, necessity := range conf.Ldap.GroupAttributes {
		if val, ok := group.Attributes[attr]; ok {
			addReq.Attribute(attr, val)
		} else if necessity == "required" {
			abort(c, errors.New("missing attribute: "+attr), http.StatusBadRequest)
			return
		}
	}

	if err := ldp.Add(addReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
}

func RemoveUser(c *gin.Context) {
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

	// First, get all groups
	filter := "(objectClass=" + conf.Ldap.GroupsObjectClassSearch + ")"
	searchReq := ldap.NewSearchRequest(conf.Ldap.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})

	result, err := ldp.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}

	// Get id of user
	id := c.Param("id")

	// For each group remove user in member
	for _, entry := range result.Entries {
		modReq := ldap.NewModifyRequest(entry.DN, []ldap.Control{})
		for _, attr := range entry.Attributes {
			if attr.Name == "member" {
				var newVal []string
				// Check all values in member, and put them in list except if our user id
				for _, value := range attr.Values {
					if value != id {
						newVal = append(newVal, value)
					}
				}
				modReq.Replace("member", attr.Values)
			}
		}

		if err := ldp.Modify(modReq); err != nil {
			abort(c, err, http.StatusInternalServerError)
			return
		}
	}

}
