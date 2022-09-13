package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

func GetUsers(c *gin.Context) {
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
	flter := c.QueryArray("filter")
	srt := c.QueryArray("sort")

	var query query
	if len(flter) > 0 {
		json.Unmarshal([]byte(flter[0]), &query)
	}

	filter := ""
	if query.Q != "" {
		filter = "(&(objectClass=" + conf.Ldap.UsersObjectClassSearch + ")(cn=*" + query.Q + "*))"
	} else {
		filter = "(&(objectClass=" + conf.Ldap.UsersObjectClassSearch + "))"
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
		fmt.Sscanf(rnge[0], "[%d,%d]", &start, &end)
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
			re, _ := regexp.Compile(`\w+`)
			params := re.FindAllString(srt[0], -1)
			switch params[1] {
			case "ASC":
				if params[0] == "attributes.displayName[0]" {
					By(displayName).Sort(entries)
				} else if params[0] == "dn" {
					By(dn).Sort(entries)
				}
			case "DESC":
				if params[0] == "attributes.displayName[0]" {
					By(reverseDisplayName).Sort(entries)
				} else if params[0] == "dn" {
					By(reverseDn).Sort(entries)
				}
			}
		}
		entries = entries[start:end]
		for _, entry := range entries {
			getGroups(c, &entry)
		}

		c.JSON(http.StatusOK, entries)
	} else {
		c.JSON(http.StatusOK, make([]string, 0))
	}

}

func UpdateUser(c *gin.Context) {
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

	var user entry
	if err := c.BindJSON(&user); err != nil {
		abort(c, err, http.StatusBadRequest)
		return
	}
	c.Set("user", user)

	modReq := ldap.NewModifyRequest(user.DN, []ldap.Control{})
	for attr, _ := range conf.Ldap.UserAttributes {
		if val, ok := user.Attributes[attr]; ok {
			modReq.Replace(attr, val)
			if attr == "memberOf" {
				setGroup(c, user.DN, val)
			}
		}
	}

	// Handle memberOf
	if val, ok := user.Attributes["memberOf"]; ok {
		setGroup(c, user.DN, val)
	}

	if err := ldp.Modify(modReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
}

func AddUser(c *gin.Context) {
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

	var user entry
	if err := c.BindJSON(&user); err != nil {
		abort(c, err, http.StatusBadRequest)
		return
	}
	c.Set("user", user)

	addReq := ldap.NewAddRequest(user.DN, []ldap.Control{})
	for attr, _ := range conf.Ldap.UserAttributes {
		if val, ok := user.Attributes[attr]; ok {
			addReq.Attribute(attr, val)
		} else {
			abort(c, errors.New("missing attribute: "+attr), http.StatusUnprocessableEntity)
			return
		}
	}
	// Handle memberOf
	if val, ok := user.Attributes["memberOf"]; ok {
		setGroup(c, user.DN, val)
	}

	if err := ldp.Add(addReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
}

func setGroup(c *gin.Context, userDN string, groupDNs []string) {
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

	// First get old groups
	filter := "(&(objectClass=*)(member=" + userDN + "))"
	searchReq := ldap.NewSearchRequest(conf.Ldap.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{}, []ldap.Control{})

	result, err := ldp.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}

	var oldGroupDNs []string
	for _, ent := range result.Entries {
		oldGroupDNs = append(oldGroupDNs, ent.DN)
	}

	// Add user to added groups
	for _, groupDN := range groupDNs {
		match := false
		for _, oldGroupDN := range oldGroupDNs {
			if groupDN == oldGroupDN {
				match = true
			}
		}
		if match {
			continue
		}
		filter := "(objectClass=*)"
		searchReq := ldap.NewSearchRequest(groupDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"member"}, []ldap.Control{})

		result, err := ldp.Search(searchReq)
		if err != nil {
			abort(c, err, http.StatusInternalServerError)
			return
		}

		values := result.Entries[0].Attributes[0].Values

		values = append(values, userDN)

		modReq := ldap.NewModifyRequest(groupDN, []ldap.Control{})
		modReq.Replace("member", values)

		if err := ldp.Modify(modReq); err != nil {
			abort(c, err, http.StatusInternalServerError)
			return
		}
	}

	//Remove user from delete groups
	for _, groupDN := range oldGroupDNs {
		match := false
		for _, oldGroupDN := range groupDNs {
			if groupDN == oldGroupDN {
				match = true
			}
		}
		if !match {
			log.Print("remove user from group:")
			log.Print(groupDN)
			filter := "(objectClass=*)"
			searchReq := ldap.NewSearchRequest(groupDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"member"}, []ldap.Control{})

			result, err := ldp.Search(searchReq)
			if err != nil {
				abort(c, err, http.StatusInternalServerError)
				return
			}

			values := result.Entries[0].Attributes[0].Values
			values = removeElement(values, userDN)

			modReq := ldap.NewModifyRequest(groupDN, []ldap.Control{})
			modReq.Replace("member", values)

			if err := ldp.Modify(modReq); err != nil {
				abort(c, err, http.StatusInternalServerError)
				return
			}
		}
	}
}

func removeElement(slice []string, elem string) []string {
	var newSlice []string
	for _, e := range slice {
		if elem != e {
			newSlice = append(newSlice, e)
		}
	}
	return newSlice
}

func SetPassword(c *gin.Context) {
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

	username, _, _ := c.Request.BasicAuth()
	userDN, _ := findUserDNAndMail(ldp, c, username)

	u, ok := c.Get("user")
	var user entry
	if !ok {
		if err := c.BindJSON(&user); err != nil {
			abort(c, err, http.StatusBadRequest)
			return
		}
	} else {
		user, _ = u.(entry)
		userDN = user.DN
	}

	if _, ok := user.Options["password"]; !ok {
		fmt.Println(user.Options)
		return
	}

	passwdModReq := ldap.NewPasswordModifyRequest(userDN, "", user.Options["password"])
	if _, err := ldp.PasswordModify(passwdModReq); err != nil {
		abort(c, err, http.StatusInternalServerError)
	}
}

func getGroups(c *gin.Context, entry *entry) {
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

	filter := "(&(objectClass=" + conf.Ldap.GroupsObjectClassSearch + ")(member=" + entry.DN + "))"
	searchReq := ldap.NewSearchRequest(conf.Ldap.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, attr, []ldap.Control{})

	result, err := ldp.Search(searchReq)
	if err != nil {
		abort(c, err, http.StatusInternalServerError)
		return
	}
	entries := prepareEntries(result.Entries)

	for _, ent := range entries {
		entry.Attributes["memberOf"] = append(entry.Attributes["memberOf"], ent.DN)
	}
}
