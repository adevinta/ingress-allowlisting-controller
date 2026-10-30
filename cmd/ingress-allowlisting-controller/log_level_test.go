package main

import (
	"testing"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/stretchr/testify/assert"
)

func TestSetLogLevel(t *testing.T) {
	orig := log.DefaultLogger.GetLevel()
	t.Cleanup(func() { log.DefaultLogger.SetLevel(orig) })

	assert.NoError(t, setLogLevel("debug"))
	assert.Equal(t, "debug", log.DefaultLogger.GetLevel().String())
	assert.NoError(t, setLogLevel("warn"))
	assert.Equal(t, "warning", log.DefaultLogger.GetLevel().String())

	err := setLogLevel("verbose")
	assert.EqualError(t, err, `unknown log level "verbose", use panic, fatal, error, warn, info, debug or trace`, "an unknown level is refused")
	assert.Equal(t, "warning", log.DefaultLogger.GetLevel().String(), "and leaves the level alone")
}
