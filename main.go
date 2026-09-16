// elfharden scans ELF binaries for the four standard hardening properties
// (PIE, NX, stack canary, RELRO) and reports them as a table or as JSON.
//
// It is the Go counterpart to the Python hardening-check tool, rewritten to
// scan whole directory trees concurrently and to fail a CI job on any binary
// that does not meet policy.
package main

import (
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"text/tabwriter"
)

// Report is one binary's result. NX and RELRO are strings because both have a
// third state: NX can be unknown, and RELRO is a three-level property.
type Report struct {
	Path   string `json:"path"`
	PIE    bool   `json:"pie"`
	NX     string `json:"nx"`
	Canary bool   `json:"canary"`
	RELRO  string `json:"relro"`
	Error  string `json:"error,omitempty"`
}

// hardened reports whether the binary meets the strict policy: PIE, a
// known-non-executable stack, a stack canary, and full RELRO.
func (r Report) hardened() bool {
	return r.Error == "" && r.PIE && r.NX == "yes" && r.Canary && r.RELRO == "full"
}

func analyze(path string) Report {
	rep := Report{Path: path}
	f, err := elf.Open(path)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	defer f.Close()

	rep.PIE = hasPIE(f)
	rep.Canary = hasCanary(f)
	rep.RELRO = relroLevel(f)
	switch nx, known := hasNX(f); {
	case !known:
		rep.NX = "unknown"
	case nx:
		rep.NX = "yes"
	default:
		rep.NX = "no"
	}
	return rep
}

// collect expands each argument into a list of candidate files. Directories
// are walked recursively; unreadable entries are skipped rather than fatal.
func collect(args []string) []string {
	var paths []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", arg, err)
			continue
		}
		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}
		filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable subtree, keep going
			}
			if d.Type().IsRegular() {
				paths = append(paths, p)
			}
			return nil
		})
	}
	return paths
}

// scan analyzes every path using a bounded worker pool.
func scan(paths []string, workers int) []Report {
	reports := make([]Report, len(paths))
	jobs := make(chan int)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				reports[idx] = analyze(paths[idx])
			}
		}()
	}
	for i := range paths {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })
	return reports
}

func writeTable(w *os.File, reports []Report, showErrors bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BINARY\tPIE\tNX\tCANARY\tRELRO")
	for _, r := range reports {
		if r.Error != "" {
			if showErrors {
				fmt.Fprintf(tw, "%s\t-\t-\t-\t-\n", r.Path)
			}
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.Path, yesno(r.PIE), r.NX, yesno(r.Canary), r.RELRO)
	}
	tw.Flush()
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func main() {
	var (
		asJSON  = flag.Bool("json", false, "emit JSON instead of a table")
		strict  = flag.Bool("strict", false, "exit 1 if any binary fails the hardening policy")
		verbose = flag.Bool("verbose", false, "include unreadable/non-ELF files in table output")
		workers = flag.Int("workers", runtime.NumCPU(), "number of concurrent workers")
	)
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "usage: elfharden [flags] <file-or-directory>...\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}

	paths := collect(flag.Args())
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no files to scan")
		os.Exit(2)
	}

	reports := scan(paths, *workers)

	// Non-ELF files are expected when walking a directory, so they are
	// filtered out of the default view rather than reported as failures.
	var usable []Report
	for _, r := range reports {
		if r.Error == "" || *verbose {
			usable = append(usable, r)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(usable); err != nil {
			fmt.Fprintf(os.Stderr, "encoding results: %v\n", err)
			os.Exit(1)
		}
	} else {
		writeTable(os.Stdout, usable, *verbose)
	}

	if *strict {
		for _, r := range usable {
			if r.Error == "" && !r.hardened() {
				os.Exit(1)
			}
		}
	}
}
