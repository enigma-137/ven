package variables

import "strings"

// Display types.
const (
	TypeSecret = "secret"
	TypeText   = "text"
)

// ValidType reports whether t is a known display type.
func ValidType(t string) bool { return t == TypeSecret || t == TypeText }

var secretSegments = map[string]bool{
	"SECRET": true, "SECRETS": true, "PASSWORD": true, "PASSWD": true, "PASS": true, "PWD": true,
	"TOKEN": true, "TOKENS": true, "KEY": true, "APIKEY": true, "CREDENTIAL": true, "CREDENTIALS": true,
	"CRED": true, "CREDS": true, "AUTH": true, "PRIVATE": true, "SIGNATURE": true, "SIGNING": true,
	"SALT": true, "PEPPER": true, "DSN": true, "SESSION": true, "COOKIE": true, "JWT": true,
	"OTP": true, "PIN": true, "CERT": true, "CERTIFICATE": true, "PEM": true, "ACCESS": true,
	"WEBHOOK": true, "HMAC": true, "ENCRYPTION": true, "CONNECTION": true, "CONNSTR": true,
}

var textSegments = map[string]bool{
	"PORT": true, "HOST": true, "HOSTNAME": true, "ENV": true, "ENVIRONMENT": true, "MODE": true,
	"DEBUG": true, "LEVEL": true, "REGION": true, "ZONE": true, "TIMEOUT": true, "TTL": true,
	"ENABLED": true, "DISABLED": true, "ENABLE": true, "DISABLE": true, "NAME": true, "VERSION": true,
	"LOCALE": true, "LANG": true, "TZ": true, "TIMEZONE": true, "COLOR": true, "THEME": true,
	"COUNT": true, "SIZE": true, "LIMIT": true, "MAX": true, "MIN": true, "PATH": true, "DIR": true,
	"FLAG": true, "FEATURE": true, "PUBLIC": true, "ORIGIN": true, "DOMAIN": true, "WORKERS": true,
	"CONCURRENCY": true, "INTERVAL": true, "RETRIES": true, "FORMAT": true, "BUCKET": true,
}

// Database-style URLs commonly embed credentials.
var credentialURLPrefixes = []string{"DATABASE", "DB", "POSTGRES", "POSTGRESQL", "PG", "MYSQL", "MONGO",
	"MONGODB", "REDIS", "AMQP", "RABBITMQ", "KAFKA", "SMTP", "MAIL", "BROKER", "CACHE", "ELASTICSEARCH"}

// Classify suggests a display type from the key name alone. It never looks
// at values and never calls external services. Unknown keys default to
// secret, the safer choice.
func Classify(key string) (typ, reason string) {
	upper := strings.ToUpper(key)
	segs := strings.FieldsFunc(upper, func(r rune) bool { return r == '_' || r == '.' || r == '-' })
	for _, s := range segs {
		if secretSegments[s] {
			return TypeSecret, "name contains " + s
		}
	}
	for _, s := range []string{"PASSWORD", "SECRET", "TOKEN", "APIKEY", "PRIVATEKEY"} {
		if strings.Contains(upper, s) {
			return TypeSecret, "name contains " + s
		}
	}
	if n := len(segs); n >= 2 && (segs[n-1] == "URL" || segs[n-1] == "URI") {
		for _, p := range credentialURLPrefixes {
			if segs[0] == p || (n > 2 && segs[n-2] == p) {
				return TypeSecret, "connection URLs often embed credentials"
			}
		}
		return TypeText, "looks like a public URL"
	}
	if len(segs) > 0 && (segs[0] == "NODE" || segs[0] == "NEXT" || segs[0] == "VITE") && len(segs) > 1 && segs[1] == "PUBLIC" {
		return TypeText, "public build-time variable"
	}
	for _, s := range segs {
		if textSegments[s] {
			return TypeText, "name suggests configuration (" + s + ")"
		}
	}
	return TypeSecret, "unrecognized name; secret by default"
}
