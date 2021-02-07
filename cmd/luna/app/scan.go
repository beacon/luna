package app

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/quay/claircore"
)

// Scan an image
func Scan(ctx context.Context, imageRef string, remote bool) error {
	return nil
}

func ScanLocal(ctx context.Context, imageRef string) error {
	return nil
}

// Manifest in custom format
type Manifest struct {
	Layers []string
}

// InspectLocal get image info from local
func InspectLocal(ctx context.Context, r string) (*Manifest, error) {
	// TODO: this is simply for docker. For container-d or cri-o, ctr code should be checked
	// k8s cri has been checked and has no features we need
	d := new(net.Dialer)
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
				return d.DialContext(ctx, "unix", "/var/run/docker.sock")
			},
		},
	}
	resp, err := client.Get("http://localhost/images/" + r + "/get")
	if err != nil {
		return nil, errors.Wrap(err, "failed to inspect image info from docker")
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("docker daemon returned status %d for image inspect of %s", resp.StatusCode, r)
	}

	tmpDir := path.Join(os.TempDir(), uuid.New().String())
	fmt.Println("Target:", tmpDir)
	if err := untar(resp.Body, tmpDir); err != nil {
		return nil, errors.Wrap(err, "failed to untar image from request")
	}

	rawManifest, err := ioutil.ReadFile(path.Join(tmpDir, "manifest.json"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to read manifest file")
	}
	var manifests []*Manifest
	if err := json.Unmarshal(rawManifest, &manifests); err != nil {
		return nil, errors.Wrap(err, "failed to decode manifest.json")
	}
	if len(manifests) != 1 {
		return nil, fmt.Errorf("unexpected manifest: length=%d", len(manifests))
	}
	return manifests[0], nil
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		if !strings.HasPrefix(path, filepath.Clean(target)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", header.Name)
		}
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, tarReader); err != nil {
			return err
		}
	}
	return nil
}

// Inspect calls external commands to inspect the specified image.
//
// The command (skopeo or docker) needs to be configured with any needed
// permissions.
func Inspect(ctx context.Context, r string) (*claircore.Manifest, error) {
	ref, err := name.ParseReference(r)
	if err != nil {
		return nil, err
	}
	fmt.Println("Ref=", ref)
	repo := ref.Context()
	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, err
	}
	rt, err := transport.New(repo.Registry, auth, http.DefaultTransport, []string{repo.Scope("pull")})
	if err != nil {
		return nil, err
	}

	desc, err := remote.Get(ref, remote.WithTransport(rt))
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}

	h, err := img.Digest()
	if err != nil {
		return nil, err
	}
	ccd, err := claircore.ParseDigest(h.String())
	if err != nil {
		return nil, err
	}
	out := claircore.Manifest{
		Hash: ccd,
	}

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}

	rURL := url.URL{
		Scheme: repo.Scheme(),
		Host:   repo.RegistryStr(),
	}
	c := http.Client{
		Transport: rt,
	}

	for _, l := range ls {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		ccd, err := claircore.ParseDigest(d.String())
		if err != nil {
			return nil, err
		}
		u, err := rURL.Parse(path.Join("/", "v2", strings.TrimPrefix(repo.RepositoryStr(), repo.RegistryStr()), "blobs", d.String()))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		res.Body.Close()

		res.Request.Header.Del("User-Agent")
		out.Layers = append(out.Layers, &claircore.Layer{
			Hash:    ccd,
			URI:     res.Request.URL.String(),
			Headers: res.Request.Header,
		})
	}

	return &out, nil
}
