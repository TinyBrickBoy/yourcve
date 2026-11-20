// Package config reads the configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string // LISTEN_ADDR, default :8080
	DatabaseURL string // DATABASE_URL
	BaseURL     string // BASE_URL, public URL incl. scheme
	SecretKey   string // SECRET_KEY, encrypts channel secrets, signs captcha

	OllamaURL     string // OLLAMA_URL, empty = no AI
	OllamaModel   string // OLLAMA_MODEL, instruct model for summaries
	EmbedModel    string // OLLAMA_EMBED_MODEL
	SummaryLang   string // SUMMARY_LANG
	AIRecentYears int    // AI_RECENT_YEARS, summaries for CVEs of the last N years (plus all with matches)
	AIConcurrency int    // AI_CONCURRENCY

	SMTPURL          string // SMTP_URL smtp://user:pass@host:587 or smtps://...:465
	SMTPFrom         string // SMTP_FROM
	EmailPerUserHour int    // EMAIL_RATE_PER_HOUR

	NVDAPIKey   string // NVD_API_KEY
	GitHubToken string // GITHUB_TOKEN (cvelistV5 commit polling, optional but recommended)
	SevenAPIKey string // SEVEN_API_KEY (Plus, later)
	StripeKey   string // STRIPE_SECRET_KEY (Plus, later)

	// ingest
	IngestEnabled   bool          // INGEST_ENABLED, default true
	IntervalCVEList time.Duration // INTERVAL_CVELIST
	IntervalNVD     time.Duration // INTERVAL_NVD
	IntervalKEV     time.Duration // INTERVAL_KEV
	IntervalOSV     time.Duration // INTERVAL_OSV
	IntervalEPSS    time.Duration // INTERVAL_EPSS
	IntervalCPE     time.Duration // INTERVAL_CPE (product catalog)
	InitialImport   bool          // INITIAL_IMPORT, bulk import of full history on first start
	OSVEcosystems   []string      // OSV_ECOSYSTEMS for the initial OSV bulk import

	RegistrationOpen     bool     // REGISTRATION_OPEN
	AdminEmails          []string // ADMIN_EMAILS
	FreeStacks           int      // FREE_MAX_STACKS
	FreeChannels         int      // FREE_MAX_CHANNELS
	MaxPerChannelHour    int      // MAX_MESSAGES_PER_CHANNEL_HOUR, above → digest
	AllowPrivateWebhooks bool     // ALLOW_PRIVATE_TARGETS, allow channel targets in private networks
	TrustProxyHeaders    bool     // TRUST_PROXY, use X-Forwarded-For / X-Real-IP
	ImprintFile          string   // IMPRINT_FILE (HTML)
	PrivacyFile          string   // PRIVACY_FILE (HTML)
	LogLevel             string   // LOG_LEVEL debug, info, warn, error
	DevInsecureCookies   bool     // DEV_INSECURE_COOKIES, allow cookies without Secure (http://localhost)
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:  env("LISTEN_ADDR", ":8080"),
		DatabaseURL: env("DATABASE_URL", ""),
		BaseURL:     strings.TrimRight(env("BASE_URL", "http://localhost:8080"), "/"),
		SecretKey:   env("SECRET_KEY", ""),

		OllamaURL:     strings.TrimRight(env("OLLAMA_URL", ""), "/"),
		OllamaModel:   env("OLLAMA_MODEL", "qwen2.5:3b-instruct"),
		EmbedModel:    env("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
		SummaryLang:   env("SUMMARY_LANG", "en"),
		AIRecentYears: envInt("AI_RECENT_YEARS", 3),
		AIConcurrency: envInt("AI_CONCURRENCY", 1),

		SMTPURL:          env("SMTP_URL", ""),
		SMTPFrom:         env("SMTP_FROM", ""),
		EmailPerUserHour: envInt("EMAIL_RATE_PER_HOUR", 30),

		NVDAPIKey:   env("NVD_API_KEY", ""),
		GitHubToken: env("GITHUB_TOKEN", ""),
		SevenAPIKey: env("SEVEN_API_KEY", ""),
		StripeKey:   env("STRIPE_SECRET_KEY", ""),

		IngestEnabled:   envBool("INGEST_ENABLED", true),
		IntervalCVEList: envDur("INTERVAL_CVELIST", time.Minute),
		IntervalNVD:     envDur("INTERVAL_NVD", time.Minute),
		IntervalKEV:     envDur("INTERVAL_KEV", time.Minute),
		IntervalOSV:     envDur("INTERVAL_OSV", time.Minute),
		IntervalEPSS:    envDur("INTERVAL_EPSS", time.Hour),
		IntervalCPE:     envDur("INTERVAL_CPE", 24*time.Hour),
		InitialImport:   envBool("INITIAL_IMPORT", true),
		OSVEcosystems:   envList("OSV_ECOSYSTEMS", "npm,PyPI,Go,Maven,crates.io,NuGet,Packagist,RubyGems,Hex,Pub,Debian,Alpine"),

		RegistrationOpen:     envBool("REGISTRATION_OPEN", true),
		AdminEmails:          envList("ADMIN_EMAILS", ""),
		FreeStacks:           envInt("FREE_MAX_STACKS", 5),
		FreeChannels:         envInt("FREE_MAX_CHANNELS", 5),
		MaxPerChannelHour:    envInt("MAX_MESSAGES_PER_CHANNEL_HOUR", 20),
		AllowPrivateWebhooks: envBool("ALLOW_PRIVATE_TARGETS", false),
		TrustProxyHeaders:    envBool("TRUST_PROXY", true),
		ImprintFile:          env("IMPRINT_FILE", ""),
		PrivacyFile:          env("PRIVACY_FILE", ""),
		LogLevel:             env("LOG_LEVEL", "info"),
		DevInsecureCookies:   envBool("DEV_INSECURE_COOKIES", false),
	}
	if c.SMTPFrom == "" {
		c.SMTPFrom = "yourcve <noreply@" + hostOf(c.BaseURL) + ">"
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(c.SecretKey) < 32 {
		errs = append(errs, errors.New("SECRET_KEY is required (at least 32 characters, e.g. openssl rand -hex 32)"))
	}
	for _, e := range []string{"INTERVAL_CVELIST", "INTERVAL_NVD", "INTERVAL_KEV", "INTERVAL_OSV", "INTERVAL_EPSS", "INTERVAL_CPE"} {
		if v := os.Getenv(e); v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", e, err))
			}
		}
	}
	return c, errors.Join(errs...)
}

func (c *Config) AIEnabled() bool    { return c.OllamaURL != "" }
func (c *Config) EmailEnabled() bool { return c.SMTPURL != "" }
func (c *Config) SecureCookies() bool {
	return strings.HasPrefix(c.BaseURL, "https://") && !c.DevInsecureCookies
}

func (c *Config) IsAdminEmail(email string) bool {
	for _, a := range c.AdminEmails {
		if strings.EqualFold(a, email) {
			return true
		}
	}
	return false
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, ":/"); i >= 0 {
		u = u[:i]
	}
	return u
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}

func envList(k, def string) []string {
	var out []string
	for _, p := range strings.Split(env(k, def), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
