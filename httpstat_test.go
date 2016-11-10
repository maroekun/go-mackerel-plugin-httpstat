package main

import "testing"

func TestGraphDefinition(t *testing.T) {
	var httpstat HttpstatPlugin

	graphdef := httpstat.GraphDefinition()
	if len(graphdef) != 1 {
		t.Errorf("GraphDefinition: %d should be 1", len(graphdef))
	}
}
