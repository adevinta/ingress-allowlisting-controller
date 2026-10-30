//go:build !race

package controllers

// raceEnabled is true when the tests are built with -race, which makes them several times slower.
const raceEnabled = false
