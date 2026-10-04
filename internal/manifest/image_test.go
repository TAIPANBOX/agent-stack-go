package manifest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The image a launcher schedules (ghcr.io/taipanbox/agent-conform) is published
// by one job of release.yml, and the way that job can go wrong is silent: lose
// the `if`, and a pull request publishes; lose the signing step, and the image
// is unsigned while the archives beside it are not. Nothing runs that job until
// somebody cuts a tag, so the shape is asserted here, on every push.
//
// The workflow is read as text, because this module has no YAML dependency and
// invariant 1 keeps it that way. jobBlock is proved against a planted workflow
// first, so "found no problem" and "could not find the job" are not the same
// result.

// jobBlock returns the text of one job under `jobs:`, from its two-space key to
// the next two-space key (or the end of the file).
func jobBlock(workflow, name string) string {
	re := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `:\s*$`)
	loc := re.FindStringIndex(workflow)
	if loc == nil {
		return ""
	}
	rest := workflow[loc[1]:]
	next := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\s*$`).FindStringIndex(rest)
	if next == nil {
		return rest
	}
	return rest[:next[0]]
}

func TestJobBlockFindsAPlantedJobAndNothingElse(t *testing.T) {
	planted := "jobs:\n  one:\n    runs-on: x\n    # a comment\n  two:\n    if: y\n  three-3:\n    z: 1\n"
	if got := jobBlock(planted, "two"); !strings.Contains(got, "if: y") || strings.Contains(got, "runs-on") || strings.Contains(got, "z: 1") {
		t.Fatalf("jobBlock(two) = %q", got)
	}
	if got := jobBlock(planted, "three-3"); !strings.Contains(got, "z: 1") {
		t.Fatalf("the last job must run to the end of the file: %q", got)
	}
	if got := jobBlock(planted, "four"); got != "" {
		t.Fatalf("an absent job must come back empty, got %q", got)
	}
}

func TestTheImageJobPublishesOnATagOnlyAndSignsWhatItPublishes(t *testing.T) {
	r := root(t)
	raw, err := os.ReadFile(filepath.Join(r, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)

	image := jobBlock(wf, "image")
	if image == "" {
		t.Fatal("release.yml has no `image` job, so the published image this repository promises is gone and every check below measured nothing")
	}
	for _, want := range []struct{ needle, why string }{
		{"if: github.event_name == 'push'", "the job that pushes must be guarded off a pull request by name (estate-gates C17)"},
		{"images: ghcr.io/${{ github.repository_owner }}/agent-conform", "it publishes the image this repository names"},
		{"flavor: latest=false", "no moving tag: a deployment pins a version"},
		{"platforms: linux/amd64,linux/arm64", "both architectures"},
		{"push: true", "it is the job that pushes"},
		{`cosign sign --yes "ghcr.io/taipanbox/agent-conform@${{ steps.push.outputs.digest }}"`, "the image is signed by digest, keyless, as the archives are"},
		{"actions/attest-build-provenance@", "the image carries a provenance attestation"},
		{"subject-digest: ${{ steps.push.outputs.digest }}", "the attestation is over the pushed digest"},
		{"id-token: write", "keyless signing needs the OIDC token"},
	} {
		if !strings.Contains(image, want.needle) {
			t.Errorf("the image job lacks %q: %s", want.needle, want.why)
		}
	}
	if strings.Contains(image, "value=latest") || strings.Contains(image, "latest=true") {
		t.Error("the image job publishes a moving :latest tag")
	}

	build := jobBlock(wf, "image-build")
	if build == "" {
		t.Fatal("release.yml has no `image-build` job: a pull request would no longer prove the Dockerfile builds")
	}
	if !strings.Contains(build, "push: false") {
		t.Error("the pull-request image build must not push")
	}
	for _, forbidden := range []string{"packages: write", "id-token: write", "docker/login-action", "cosign sign"} {
		if strings.Contains(build, forbidden) {
			t.Errorf("the no-push image build carries %q, which only the publishing job may", forbidden)
		}
	}

	// A change to the Dockerfile must run the build job that proves it.
	pr := regexp.MustCompile(`(?m)^  pull_request:\s*\n\s+paths:\s*\[([^\]]*)\]`).FindStringSubmatch(wf)
	if pr == nil || !strings.Contains(pr[1], `"Dockerfile"`) {
		t.Errorf("the pull_request trigger does not name the Dockerfile in its paths, so an edit to it is first built by a tag")
	}
}

func TestTheDockerfileIsStaticNonRootAndNamesTheCommand(t *testing.T) {
	r := root(t)
	raw, err := os.ReadFile(filepath.Join(r, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(raw)
	for _, want := range []string{
		"./cmd/agent-conform",
		"USER 65532:65532",
		`ENTRYPOINT ["/usr/local/bin/agent-conform"]`,
		"FROM gcr.io/distroless/static-debian12@sha256:",
		"CGO_ENABLED=0",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
}
