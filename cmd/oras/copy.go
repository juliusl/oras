package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/containerd/containerd/reference"
	"github.com/deislabs/oras/pkg/content"
	ctxo "github.com/deislabs/oras/pkg/context"
	"github.com/deislabs/oras/pkg/oras"
	"github.com/deislabs/oras/pkg/remotes/docker"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type copyOptions struct {
	from                   pullOptions
	fromDiscover           discoverOptions
	to                     pushOptions
	rescursive             bool
	keep                   bool
	matchAnnotationInclude []string
	matchAnnotationExclude []string
}

type copyObject struct {
	digest       digest.Digest
	name         string
	subject      string
	artifactType string
	mediaType    string
	size         int64
	annotations  map[string]string
}

type copyRecursiveOptions struct {
	memoryStore     *content.Memorystore
	additionalFiles []copyObject
	filter          func(artifactspec.Descriptor) bool
	artifactType    string
}

func copyCmd() *cobra.Command {
	var opts copyOptions
	cmd := &cobra.Command{
		Use:     "copy <from-ref> <to-ref>",
		Aliases: []string{"cp"},
		Short:   "Copy files from ref to ref",
		Long: `Copy artifacts from one reference to another reference
	# Examples 

	## Copy image only 
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1

	## Copy image and artifacts
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1 -r

	# Advanced Examples - Copying with annotation filters 

	## Copy image and artifacts with match include filter
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1 -r -m annotation.name /test/

	## Copy image and artifacts with match exclude filter
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1 -r -x annotation.name /test/

	## Copy image with both filters
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1 -r -m annotation.name /test/ -x other.annotation.name /test/

	## Copy image with multiple match expressions 
	oras cp localhost:5000/net-monitor:v1 localhost:5000/net-monitor-copy:v1 -r -m annotation.name /test/ -m other.annotation.name /test/
		`,
		Args: cobra.MinimumNArgs(2),
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
	cmd.Flags().BoolVarP(&opts.keep, "keep", "k", false, "keep source files that were copied")
	cmd.Flags().StringArrayVarP(&opts.matchAnnotationInclude, "match-annotation-include", "m", nil, "provide an annotation name and regular expression, matches will be included (only applicable with --recursive and -r)")
	cmd.Flags().StringArrayVarP(&opts.matchAnnotationExclude, "match-annotation-exclude", "x", nil, "provide an annotation name and regular expression, matches will be excluded (only applicable with --recursive and -r)")

	return cmd
}

func runCopy(opts copyOptions) error {
	var tocopy []copyObject

	err := os.RemoveAll(".working")
	if err != nil {
		return err
	}

	err = os.Mkdir(".working", 0755)
	if err != nil {
		return err
	}

	store := content.NewMemoryStore()

	var recursiveOptions *copyRecursiveOptions
	if opts.rescursive {
		recursiveOptions = &copyRecursiveOptions{
			artifactType: opts.fromDiscover.artifactType,
			memoryStore:  store,
		}

		if opts.matchAnnotationInclude != nil || opts.matchAnnotationExclude != nil {
			recursiveOptions.filter = build_match_filter(opts.matchAnnotationInclude, opts.matchAnnotationExclude)
		}
	}

	desc, pulled, err := copy_source(opts.from, opts.to.targetRef, recursiveOptions)
	if err != nil {
		return err
	}

	initialCopyObject := copy_object_from_descriptor(desc, copyObject{})
	tocopy = append(tocopy, initialCopyObject)

	for _, p := range pulled {
		tocopy = append(tocopy, copy_object_from_descriptor(p, initialCopyObject))
	}

	if opts.rescursive {
		for _, r := range recursiveOptions.additionalFiles {
			d, content, ok := recursiveOptions.memoryStore.Get(ocispec.Descriptor{
				Size:        r.size,
				Annotations: r.annotations,
				MediaType:   r.mediaType,
				Digest:      r.digest,
			})

			if !ok {
				continue
			}

			tocopy = append(tocopy, r)

			switch d.MediaType {
			case artifactspec.MediaTypeArtifactManifest:
				m := &manifest_extended{}
				err := json.Unmarshal(content, m)
				if err != nil {
					return err
				}

				for _, b := range m.Blobs {
					var name string

					if b.Annotations != nil {
						name = b.Annotations[ocispec.AnnotationTitle]
					}

					tocopy = append(tocopy, copyObject{
						digest:       b.Digest,
						name:         name,
						subject:      r.subject,
						artifactType: r.artifactType,
						mediaType:    b.MediaType,
						size:         b.Size,
						annotations:  b.Annotations,
					})
				}
			}
		}
	}

	for _, c := range tocopy {
		d, content, ok := recursiveOptions.memoryStore.Get(ocispec.Descriptor{
			Size:        c.size,
			Annotations: c.annotations,
			MediaType:   c.mediaType,
			Digest:      c.digest,
		})

		if ok {
			fmt.Printf("%v\n%s\n", d, string(content))
		}
	}

	// if !opts.keep {
	// 	for _, f := range toclean {
	// 		if strings.Index(f, ":") > 0 {
	// 			os.Remove(f[:strings.Index(f, ":")])
	// 		} else {
	// 			os.Remove(f)
	// 		}
	// 	}
	// }

	return nil
}

func copy_object_from_descriptor(b ocispec.Descriptor, referrer copyObject) copyObject {
	var name string

	if b.Annotations != nil {
		name = b.Annotations[ocispec.AnnotationTitle]
	}

	return copyObject{
		digest:       b.Digest,
		name:         name,
		subject:      referrer.subject,
		artifactType: referrer.artifactType,
		mediaType:    b.MediaType,
		size:         b.Size,
		annotations:  b.Annotations,
	}
}

func build_match_filter(matchInclude []string, matchExclude []string) func(a artifactspec.Descriptor) bool {
	var (
		includes map[string]*regexp.Regexp = make(map[string]*regexp.Regexp)
		excludes map[string]*regexp.Regexp = make(map[string]*regexp.Regexp)
	)

	for _, m := range matchInclude {
		args := strings.Split(m, " ")
		if len(args) > 0 {
			annotationTitle := args[0]
			annotationFilter := args[1]
			includes[annotationTitle] = regexp.MustCompile(strings.Trim(annotationFilter, "/"))
		}
	}

	for _, m := range matchExclude {
		args := strings.Split(m, " ")
		if len(args) > 0 {
			annotationTitle := args[0]
			annotationFilter := args[1]
			excludes[annotationTitle] = regexp.MustCompile(strings.Trim(annotationFilter, "/"))
		}
	}

	return func(a artifactspec.Descriptor) bool {
		if a.Annotations == nil {
			return len(includes) <= 0
		}

		result := true
		for k, v := range a.Annotations {
			matchFn, ok := includes[k]
			if ok {
				result = result && matchFn.MatchString(v)
			}

			matchFn, ok = excludes[k]
			if ok {
				result = result && !matchFn.MatchString(v)
			}

			// If it already should be filtered just return, otherwise continue to check all annotations
			if !result {
				return result
			}
		}

		return result
	}
}

func copy_source(source pullOptions, destref string, recursiveOptions *copyRecursiveOptions) (ocispec.Descriptor, []ocispec.Descriptor, error) {
	if source.output == "" {
		source.output = ".working"
	}

	desc, pulled, err := copy_pull(source, recursiveOptions.memoryStore)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	if recursiveOptions != nil {
		discoverOpts := discoverOptions{
			targetRef:    source.targetRef,
			artifactType: recursiveOptions.artifactType,
		}

		runDiscover(&discoverOpts)

		_, host, namespace, _, err := parse(source.targetRef)
		if err != nil {
			return ocispec.Descriptor{}, nil, err
		}

		for _, a := range *discoverOpts.outputRefs {
			match := func(artifactspec.Descriptor) bool {
				return true
			}

			if recursiveOptions.filter != nil {
				match = recursiveOptions.filter
			}

			if match(a) {
				opts := pullOptions{
					targetRef:          fmt.Sprintf("%s/%s@%s", host, namespace, a.Digest),
					allowAllMediaTypes: true,
					allowEmptyName:     true,
					output:             fmt.Sprintf(".working/%s", strings.Replace(a.Digest.String(), ":", "-", -1)),
				}

				_, _, destnamespace, _, err := parse(destref)
				if err != nil {
					return ocispec.Descriptor{}, nil, err
				}

				name := a.Annotations[ocispec.AnnotationTitle]

				recursiveOptions.additionalFiles = append(recursiveOptions.additionalFiles, struct {
					digest       digest.Digest
					name         string
					subject      string
					artifactType string
					mediaType    string
					size         int64
					annotations  map[string]string
				}{
					digest:       a.Digest,
					name:         name,
					annotations:  a.Annotations,
					size:         a.Size,
					subject:      destref,
					artifactType: a.ArtifactType,
					mediaType:    a.MediaType,
				})

				destRef := fmt.Sprintf("%s/%s@%s", host, destnamespace, a.Digest)

				desc, pulled, err := copy_source(opts, destRef, recursiveOptions)
				if err != nil {
					return ocispec.Descriptor{}, nil, err
				}

				fmt.Printf("Pulled %v, %v\n", desc, pulled)
			}
		}
	}

	fmt.Printf("Pulled %v, %v\n", desc, pulled)

	return desc, pulled, nil
}

func copy_pull(opts pullOptions, store *content.Memorystore) (ocispec.Descriptor, []ocispec.Descriptor, error) {
	ctx := context.Background()
	if opts.debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else if !opts.verbose {
		ctx = ctxo.WithLoggerDiscarded(ctx)
	}
	if opts.allowAllMediaTypes {
		opts.allowedMediaTypes = nil
	} else if len(opts.allowedMediaTypes) == 0 {
		opts.allowedMediaTypes = []string{content.DefaultBlobMediaType, content.DefaultBlobDirMediaType}
	}

	resolver, ropts := newResolver(opts.username, opts.password, opts.insecure, opts.plainHTTP, opts.configs...)

	resolver, err := docker.WithDiscover(opts.targetRef, resolver, ropts)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	pullOpts := []oras.PullOpt{
		oras.WithAllowedMediaTypes(opts.allowedMediaTypes),
		oras.WithPullStatusTrack(os.Stdout),
	}

	if opts.allowEmptyName {
		pullOpts = append(pullOpts, oras.WithPullEmptyNameAllowed())
	}

	desc, artifacts, err := oras.Pull(ctx, resolver, opts.targetRef, store, pullOpts...)
	if err != nil {
		if err == reference.ErrObjectRequired {
			return ocispec.Descriptor{}, nil, fmt.Errorf("image reference format is invalid. Please specify <name:tag|name@digest>")
		}
		return ocispec.Descriptor{}, nil, err
	}
	if len(artifacts) == 0 {
		fmt.Println("Downloaded empty artifact")
	}

	return desc, artifacts, nil
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

type manifest_extended struct {
	// MediaType is the media type of this descriptor, this isn't included in the artifactspec, but can appear
	MediaType string `json:"mediaType,omitempty"`

	// ArtifactType is the artifact type of the object this schema refers to.
	ArtifactType string `json:"artifactType"`

	// Blobs is a collection of blobs referenced by this manifest.
	Blobs []ocispec.Descriptor `json:"blobs"`

	// Subject is an optional reference to any existing manifest within the repository.
	// When specified, the artifact is said to be dependent upon the referenced subject.
	Subject ocispec.Descriptor `json:"subject"`

	// Annotations contains arbitrary metadata for the artifact manifest.
	Annotations map[string]string `json:"annotations,omitempty"`
}
