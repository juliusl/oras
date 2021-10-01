package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"

	"github.com/spf13/cobra"
)

type copyOptions struct {
	from         pullOptions
	fromDiscover discoverOptions
	to           pushOptions
	rescursive   bool
}

func copyCmd() *cobra.Command {
	var opts copyOptions
	cmd := &cobra.Command{
		Use:     "copy <from-ref> <to-ref>",
		Aliases: []string{"cp"},
		Short:   "Copy files from ref to ref",
		Long:    `Copy artifacts from one reference to another reference`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.from.targetRef = args[0]
			opts.to.targetRef = args[1]
			return runCopy(opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.from.allowedMediaTypes, "from-media-type", nil, "allowed media types to be pulled")
	cmd.Flags().BoolVar(&opts.from.allowAllMediaTypes, "from-allow-all", false, "allow all media types to be pulled")
	cmd.Flags().BoolVar(&opts.from.allowEmptyName, "from-allow-empty-name", false, "allow pulling files with empty name")
	cmd.Flags().BoolVar(&opts.from.keepOldFiles, "from-keep-old-files", false, "do not replace existing files when pulling, treat them as errors")
	cmd.Flags().BoolVar(&opts.from.pathTraversal, "from-allow-path-traversal", false, "allow storing files out of the output directory")
	cmd.Flags().StringVar(&opts.from.output, "from-output", "", "output directory")
	cmd.Flags().BoolVar(&opts.from.verbose, "from-verbose", false, "verbose output")
	cmd.Flags().BoolVar(&opts.from.debug, "from-debug", false, "debug mode")
	cmd.Flags().StringArrayVar(&opts.from.configs, "from-config", nil, "auth config path")
	cmd.Flags().StringVar(&opts.from.username, "from-username", "", "registry username")
	cmd.Flags().StringVar(&opts.from.password, "from-password", "", "registry password")
	cmd.Flags().BoolVar(&opts.from.insecure, "from-insecure", false, "allow connections to SSL registry without certs")
	cmd.Flags().BoolVar(&opts.from.plainHTTP, "from-plain-http", false, "use plain http and not https")

	cmd.Flags().StringVarP(&opts.fromDiscover.artifactType, "artifact-type", "", "", "artifact type")
	cmd.Flags().StringVarP(&opts.fromDiscover.outputType, "output", "o", "table", fmt.Sprintf("Format in which to display references (%s, %s, or %s). tree format will show all references including nested", "table", "json", "tree"))
	cmd.Flags().BoolVarP(&opts.fromDiscover.verbose, "verbose", "v", false, "verbose output")
	cmd.Flags().BoolVarP(&opts.fromDiscover.debug, "debug", "d", false, "debug mode")
	cmd.Flags().StringArrayVarP(&opts.fromDiscover.configs, "config", "c", nil, "auth config path")
	cmd.Flags().StringVarP(&opts.fromDiscover.username, "username", "u", "", "registry username")
	cmd.Flags().StringVarP(&opts.fromDiscover.password, "password", "p", "", "registry password")
	cmd.Flags().BoolVarP(&opts.fromDiscover.insecure, "insecure", "", false, "allow connections to SSL registry without certs")
	cmd.Flags().BoolVarP(&opts.fromDiscover.plainHTTP, "plain-http", "", false, "use plain http and not https")

	cmd.Flags().StringVar(&opts.to.manifestConfigRef, "to-manifest-config", "", "manifest config file")
	cmd.Flags().StringVar(&opts.to.manifestAnnotations, "to-manifest-annotations", "", "manifest annotation file")
	cmd.Flags().StringVar(&opts.to.manifestExport, "to-export-manifest", "", "export the pushed manifest")
	cmd.Flags().StringVar(&opts.to.artifactType, "to-artifact-type", "", "artifact type")
	cmd.Flags().StringVar(&opts.to.artifactRefs, "to-subject", "", "subject artifact")
	cmd.Flags().BoolVar(&opts.to.pathValidationDisabled, "to-disable-path-validation", false, "skip path validation")
	cmd.Flags().BoolVar(&opts.to.verbose, "to-verbose", false, "verbose output")
	cmd.Flags().BoolVar(&opts.to.debug, "to-debug", false, "debug mode")
	cmd.Flags().StringArrayVar(&opts.to.configs, "to-config", nil, "auth config path")
	cmd.Flags().StringVar(&opts.to.username, "to-username", "", "registry username")
	cmd.Flags().StringVar(&opts.to.password, "to-password", "", "registry password")
	cmd.Flags().BoolVar(&opts.to.insecure, "to-insecure", false, "allow connections to SSL registry without certs")
	cmd.Flags().BoolVar(&opts.to.plainHTTP, "to-plain-http", false, "use plain http and not https")
	cmd.Flags().BoolVar(&opts.to.dryRun, "to-dry-run", false, "push to a dummy registry instead of the actual remote registry")

	cmd.Flags().BoolVarP(&opts.rescursive, "recursive", "r", false, "recursively copy artifacts that reference the artifact being copied")

	return cmd
}

func runCopy(opts copyOptions) error {
	err := os.RemoveAll(".working")
	if err != nil {
		return err
	}

	err = os.Mkdir(".working", 0755)
	if err != nil {
		return err
	}

	opts.from.output = ".working"

	err = runPull(opts.from)
	if err != nil {
		return err
	}

	files, err := ioutil.ReadDir(".working")
	if err != nil {
		log.Fatal(err)
	}

	inputFiles := make([]string, len(files))

	for i, f := range files {
		inputFiles[i] = f.Name()
	}

	opts.to.fileRefs = inputFiles

	err = runPush(&opts.to)
	if err != nil {
		return err
	}

	if opts.rescursive {
		discOpts := &opts.fromDiscover
		discOpts.targetRef = opts.from.targetRef
		err := runDiscover(discOpts)
		if err != nil {
			return err
		}

		_, _, namespace, _, err := parse(opts.from.targetRef)
		if err != nil {
			return err
		}

		_, host, _, _, err := parse(opts.to.targetRef)
		if err != nil {
			return err
		}

		subject := opts.to.targetRef

		for _, r := range *discOpts.refs {
			toOpts := &opts.to

			toOpts.targetRef = fmt.Sprintf("%s/%s@%s", host, namespace, r.Digest)
			toOpts.artifactType = r.ArtifactType
			toOpts.artifactRefs = subject

			err = runPush(toOpts)
			if err != nil {
				return err
			}
		}
	}

	for _, f := range files {
		os.Remove(f.Name())
	}

	return nil
}

var (
	referenceRegex = regexp.MustCompile(`([.\w\d:-]+)\/{1,}?([a-z0-9]+(?:[/._-][a-z0-9]+)*(?:[a-z0-9]+(?:[/._-][a-z0-9]+)*)*)[:@]([a-zA-Z0-9_]+:?[a-zA-Z0-9._-]{0,127})`)
)

func parse(parsing string) (reference string, host string, namespace string, locator string, err error) {
	matches := referenceRegex.FindAllStringSubmatch(parsing, -1)
	// Technically a namespace is allowed to have "/"'s, while a reference is not allowed to
	// That means if you string match the reference regex, then you should end up with basically the first segment being the host
	// the middle part being the namespace
	// and the last part should be the tag

	// This should be the case most of the time
	if len(matches[0]) == 4 {
		return matches[0][0], matches[0][1], matches[0][2], matches[0][3], nil
	}

	return "", "", "", "", errors.New("could not parse reference")
}
