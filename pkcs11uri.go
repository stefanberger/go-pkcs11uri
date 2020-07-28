package pkcs11uri

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Pkcs11URI holds a pkcs11 URI object
type Pkcs11URI struct {
	// path and query attributes may have custom attributes that either
	// have to be in the query or in the path part, so we use two maps
	pathAttributes  map[string]string
	queryAttributes map[string]string
	// directories to search for pkcs11 modules
	moduleDirectories []string
	// file paths of allowed pkcs11 modules
	allowedModulePaths []string
}

// upper character hex digits needed for pct-encoding
const hex = "0123456789ABCDEF"

// escapeAll pct-escapes all characters in the string
func escapeAll(s string) string {
	res := make([]byte, len(s)*3)
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		res[j] = '%'
		res[j+1] = hex[c>>4]
		res[j+2] = hex[c&0xf]
		j += 3
	}
	return string(res)
}

// escape pct-escapes the path and query part of the pkcs11 URI following the different rules of the
// path and query part as decribed in RFC 7512 sec. 2.3
func escape(s string, isPath bool) string {
	res := make([]byte, len(s)*3)
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		// unreserved per RFC 3986 sec. 2.3
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			res[j] = c
		} else if isPath && c == '&' {
			res[j] = c
		} else if !isPath && (c == '/' || c == '?' || c == '|') {
			res[j] = c
		} else {
			switch c {
			case '-', '.', '_', '~': // unreserved per RFC 3986 sec. 2.3
				res[j] = c
			case ':', '[', ']', '@', '!', '$', '`', '(', ')', '*', '+', ',', '=':
				res[j] = c
			default:
				res[j] = '%'
				res[j+1] = hex[c>>4]
				res[j+2] = hex[c&0xf]
				j += 2
			}
		}
		j++
	}
	return string(res[:j])
}

// New creates a new Pkcs11URI object
func New() (Pkcs11URI, error) {
	return Pkcs11URI{
		pathAttributes:  make(map[string]string),
		queryAttributes: make(map[string]string),
	}, nil
}

func (uri *Pkcs11URI) addAttribute(attrMap map[string]string, name, value string) error {
	v, err := url.QueryUnescape(value)
	if err != nil {
		return err
	}
	attrMap[name] = v
	return nil
}

// GetPathAttribute returns the value of a path attribute
func (uri *Pkcs11URI) GetPathAttribute(name string) (string, bool) {
	v, ok := uri.pathAttributes[name]
	return v, ok
}

// AddPathAttribute adds a path attribute
func (uri *Pkcs11URI) AddPathAttribute(name, value string) error {
	if _, ok := uri.pathAttributes[name]; ok {
		return errors.New("duplicate path attribute")
	}
	return uri.addAttribute(uri.pathAttributes, name, value)
}

// RemovePathAttribute removes a path attribute
func (uri *Pkcs11URI) RemovePathAttribute(name string) {
	delete(uri.pathAttributes, name)
}

// GetQueryAttribute returns the value of a query attribute
func (uri *Pkcs11URI) GetQueryAttribute(name string) (string, bool) {
	v, ok := uri.queryAttributes[name]
	return v, ok
}

// AddQueryAttribute adds a query attribute
func (uri *Pkcs11URI) AddQueryAttribute(name, value string) error {
	if _, ok := uri.queryAttributes[name]; ok {
		return errors.New("duplicate query attribute")
	}
	return uri.addAttribute(uri.queryAttributes, name, value)
}

// RemoveQueryAttribute removes a path attribute
func (uri *Pkcs11URI) RemoveQueryAttribute(name string) {
	delete(uri.queryAttributes, name)
}

// Validate validates a Pkcs11URI object's attributes following RFC 7512 rules and proper formatting of
// their values
func (uri *Pkcs11URI) Validate() error {
	/* RFC 7512: 2.3 */
	/* slot-id should be DIGIT, but we go for number */
	if v, ok := uri.pathAttributes["slot-id"]; ok {
		if _, err := strconv.Atoi(v); err != nil {
			return fmt.Errorf("slot-id must be a number: %s", v)
		}
	}

	/* library-version should 1*DIGIT [ "." 1 *DIGIT ]; allow NUMBERS for DIGIT */
	if v, ok := uri.pathAttributes["library-version"]; ok {
		m, err := regexp.Match("^[0-9]+(\\.[0-9]+)?$", []byte(v))
		if err != nil || !m {
			return fmt.Errorf("Invalid format for library-version '%s'", v)
		}
	}

	if v, ok := uri.pathAttributes["type"]; ok {
		m, err := regexp.Match("^(public|private|cert|secret-key}data)?$", []byte(v))
		if err != nil || !m {
			return fmt.Errorf("Invalid type '%s'", v)
		}
	}

	/* RFC 7512: 2.4 */
	_, ok1 := uri.queryAttributes["pin-source"]
	_, ok2 := uri.queryAttributes["pin-value"]
	if ok1 && ok2 {
		return errors.New("URI must not contain pin-source and pin-value")
	}

	if v, ok := uri.queryAttributes["module-path"]; ok {
		if !filepath.IsAbs(v) {
			return fmt.Errorf("path %s of module-name attribute must be absolute", v)
		}
	}

	return nil
}

// GetPIN gets the PIN from either the pin-value or pin-source attribute
func (uri *Pkcs11URI) GetPIN() (string, error) {
	if v, ok := uri.queryAttributes["pin-value"]; ok {
		return v, nil
	}
	if v, ok := uri.queryAttributes["pin-source"]; ok {
		pinuri, err := url.ParseRequestURI(v)
		if err != nil {
			return "", fmt.Errorf("Could not parse pin-source: %s ", err)
		}
		switch pinuri.Scheme {
		case "", "file":
			if !filepath.IsAbs(pinuri.Path) {
				return "", fmt.Errorf("PIN URI path '%s' is not absolute", pinuri.Path)
			}
			pin, err := ioutil.ReadFile(pinuri.Path)
			if err != nil {
				return "", fmt.Errorf("Could not open PIN file: %s", err)
			}
			return string(pin), nil
		default:
			return "", fmt.Errorf("PIN URI scheme %s is not supported", pinuri.Scheme)
		}
	}
	return "", fmt.Errorf("Neither pin-source nor pin-value are available")
}

// Parse parses a pkcs11: URI string
func (uri *Pkcs11URI) Parse(uristring string) error {
	if !strings.HasPrefix(uristring, "pkcs11:") {
		return errors.New("Malformed pkcs11 URI: missing pcks11: prefix")
	}
	parts := strings.Split(uristring[7:], "?")
	if len(parts) > 2 {
		return errors.New("Malformed pkcs11 URI: too many query parts")
	}

	uri.pathAttributes = make(map[string]string)
	uri.queryAttributes = make(map[string]string)

	if len(parts[0]) > 0 {
		/* parse path part */
		for _, part := range strings.Split(parts[0], ";") {
			p := strings.Split(part, "=")
			if len(p) != 2 {
				return errors.New("Malformed pkcs11 URI: malformed path attribute")
			}
			if err := uri.AddPathAttribute(p[0], p[1]); err != nil {
				return fmt.Errorf("Malformed pkcs11 URI: %s", err)
			}
		}
	}

	if len(parts) == 2 {
		/* parse query part */
		for _, part := range strings.Split(parts[1], "&") {
			p := strings.Split(part, "=")
			if len(p) != 2 {
				return errors.New("Malformed pkcs11 URI: malformed query attribute")
			}
			if err := uri.AddQueryAttribute(p[0], p[1]); err != nil {
				return fmt.Errorf("Malformed pkcs11 URI: %s", err)
			}
		}
	}
	return uri.Validate()
}

// formatAttribute formats attributes and escapes their values as needed
func formatAttributes(attrMap map[string]string, ispath bool) string {
	res := ""
	for key, value := range attrMap {
		switch key {
		case "id":
			/* id is always pct-encoded */
			value = escapeAll(value)
		default:
			if ispath {
				value = escape(value, true)
			} else {
				value = escape(value, false)
			}
		}
		if len(res) > 0 {
			res += ";"
		}
		res += key + "=" + value
	}
	return res
}

// Format formats a Pkcs11URI to it string representaion
func (uri *Pkcs11URI) Format() (string, error) {
	if err := uri.Validate(); err != nil {
		return "", err
	}
	result := "pkcs11:" + formatAttributes(uri.pathAttributes, true)
	if len(uri.queryAttributes) > 0 {
		result += "?" + formatAttributes(uri.queryAttributes, false)
	}
	return result, nil
}

// SetModuleDirectories sets the search directories for pkcs11 modules
func (uri *Pkcs11URI) SetModuleDirectories(moduleDirectories []string) {
	uri.moduleDirectories = moduleDirectories
}

// GetModuleDirectories gets the search directories for pkcs11 modules
func (uri *Pkcs11URI) GetModuleDirectories() []string {
	return uri.moduleDirectories
}

// SetAllowedModulePaths sets allowed module paths to restrict access to modules. By
// default no filtering is done.
// Directory entries must end with a '/', all other ones are assumed to be file entries.
// Allowed modules are filtered by string matching.
func (uri *Pkcs11URI) SetAllowedModulePaths(allowedModulePaths []string) {
	uri.allowedModulePaths = allowedModulePaths
}

func (uri *Pkcs11URI) isAllowedPath(path string) bool {
	if len(uri.allowedModulePaths) == 0 {
		return true
	}
	for _, allowedPath := range uri.allowedModulePaths {
		if allowedPath == path {
			// exact filename match
			return true
		}
		if allowedPath[len(allowedPath)-1] == '/' && strings.HasPrefix(path, allowedPath) {
			// allowedPath no subdirectory is allowed
			idx := strings.IndexRune(path[len(allowedPath):], os.PathSeparator)
			if idx < 0 {
				return true
			}
		}
	}
	return false
}

// GetModule returns the module to use or an error in case no module could be found.
// First the module-path is checked for whether it holds an absolute that can be read
// by the current user. If this is the case the module is returned. Otherwise either the module-path
// is used or the user-provided module path is used to match a module containing what is set in the
// attribute module-name.
func (uri *Pkcs11URI) GetModule() (string, error) {
	var searchdirs []string
	v, ok := uri.queryAttributes["module-path"]

	if ok {
		info, err := os.Stat(v)
		if err != nil {
			return "", fmt.Errorf("module-path '%s' is not accessible", v)
		}
		if err == nil && info.Mode().IsRegular() && uri.isAllowedPath(v) {
			// it's a file
			return v, nil
		}
		if !info.IsDir() {
			return "", fmt.Errorf("module-path '%s' points to an invalid file type", v)
		}
		// v is a directory
		searchdirs = []string{v}
	} else {
		searchdirs = uri.GetModuleDirectories()
	}

	moduleName, ok := uri.queryAttributes["module-name"]
	if !ok {
		return "", fmt.Errorf("module-name attribute is not set")
	}
	moduleName = strings.ToLower(moduleName)

	for _, dir := range searchdirs {
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, file := range files {
			fileLower := strings.ToLower(file.Name())

			i := strings.Index(fileLower, moduleName)
			if i < 0 {
				continue
			}
			// we require that the fileLower ends with moduleName or that
			// a suffix follows so that softhsm will not match libsofthsm2.so but only
			// libsofthsm.so
			if len(fileLower) == i+len(moduleName) || fileLower[i+len(moduleName)] == '.' {
				f := filepath.Join(dir, file.Name())
				if uri.isAllowedPath(f) {
					return f, nil
				}
			}
		}
	}
	return "", fmt.Errorf("No module could be found")
}
