package main

import (
	"flag"
	"fmt"
	"sort"
)

const generalFlagGroup = "General"

// flagGroups maps a flag name to its -help group. Flags not registered through flagGroup (e.g.
// -kubeconfig, registered by controller-runtime) are shown under General.
var flagGroups = map[string]string{}

// flagGroup registers the flags declared in register under a -help group.
func flagGroup(title string, register func()) {
	before := map[string]bool{}
	flag.VisitAll(func(f *flag.Flag) { before[f.Name] = true })
	register()
	flag.VisitAll(func(f *flag.Flag) {
		if !before[f.Name] {
			flagGroups[f.Name] = title
		}
	})
}

// printUsage prints the flags of fs by group: General first, then the other groups alphabetically,
// flags alphabetically within a group, each in the same format as flag.PrintDefaults.
func printUsage(fs *flag.FlagSet, groups map[string]string) {
	out := fs.Output()
	fmt.Fprintf(out, "Usage of %s:\n", fs.Name())

	byGroup := map[string]*flag.FlagSet{}
	var titles []string
	fs.VisitAll(func(f *flag.Flag) { // VisitAll is alphabetical
		title, ok := groups[f.Name]
		if !ok {
			title = generalFlagGroup
		}
		if byGroup[title] == nil {
			byGroup[title] = flag.NewFlagSet(title, flag.ContinueOnError)
			byGroup[title].SetOutput(out)
			titles = append(titles, title)
		}
		// Re-register the flag in its group's set so PrintDefaults formats it; keep the original
		// default, as Var records the current value.
		byGroup[title].Var(f.Value, f.Name, f.Usage)
		byGroup[title].Lookup(f.Name).DefValue = f.DefValue
	})

	sort.Slice(titles, func(i, j int) bool {
		if (titles[i] == generalFlagGroup) != (titles[j] == generalFlagGroup) {
			return titles[i] == generalFlagGroup
		}
		return titles[i] < titles[j]
	})
	for _, title := range titles {
		fmt.Fprintf(out, "\n# %s\n", title)
		byGroup[title].PrintDefaults()
	}
}
