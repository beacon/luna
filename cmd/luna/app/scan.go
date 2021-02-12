package app

import (
	"archive/tar"
	"bytes"
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
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libindex"
)

// Scan an image
func Scan(ctx context.Context, imageRef string, remote bool) error {
	return nil
}

// Scan local images
func ScanLocal(ctx context.Context, imageRef, dsn string) error {
	m, err := InspectLocal(ctx, imageRef)
	if err != nil {
		return err
	}
	idx, err := libindex.New(ctx, &libindex.Opts{
		ConnString: dsn,
	})
	if err != nil {
		return errors.Wrap(err, "failed to setup libindex")
	}
	report, err := idx.Index(ctx, m)
	if err != nil {
		return errors.Wrap(err, "failed to make report")
	}
	fmt.Println(report)
	return nil
}

// Manifest in docker json
type Manifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// InspectLocal get image info from local
func InspectLocal(ctx context.Context, r string) (*claircore.Manifest, error) {
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
	digest, size, err := v1.SHA256(bytes.NewReader(rawManifest))
	if err != nil {
		return nil, errors.Wrap(err, "failed to make manifest digest")
	}
	type tmpLayer struct {
		Hash string `json:"hash"`
		URI  string `json:"uri"`
	}
	tmpManifest := struct {
		Hash   v1.Hash    `json:"hash"`
		Size   int64      `json:"size"`
		Layers []tmpLayer `json:"layers"`
	}{
		Hash:   digest,
		Size:   size,
		Layers: make([]tmpLayer, len(manifests[0].Layers)),
	}
	for i, l := range manifests[0].Layers {
		localPath := path.Join(tmpDir, l)
		tmpManifest.Layers[i].Hash = "sha256:" + strings.TrimSuffix(l, "/layer.tar")
		tmpManifest.Layers[i].URI = "file:///" + localPath
	}

	var clairManifest claircore.Manifest
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&tmpManifest); err != nil {
		return nil, errors.Wrap(err, "failed to encode temp manifest")
	}
	fmt.Println("DBG - Clair Manifest\n", buf.String())
	if err := json.NewDecoder(&buf).Decode(&clairManifest); err != nil {
		return nil, errors.Wrap(err, "failed to decode clair manifest")
	}

	return &clairManifest, nil
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)
	if err := os.MkdirAll(target, 0744); err != nil {
		return errors.Wrap(err, "failed to create target dir")
	}
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
