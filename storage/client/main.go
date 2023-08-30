package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	rpb "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/enfabrica/enkit/lib/config/defcon"
	"github.com/enfabrica/enkit/lib/config/identity"
	"github.com/enfabrica/enkit/lib/khttp/kcookie"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	remoteAddr = flag.String("remote_addr", "bb-scheduler.gcp02.corp.enfabrica.net:443", "Address for the remote cas server")
	targetPath = flag.String("path", "", "The path to the file or directory to upload")
)

func main() {
	flag.Parse()

	if *targetPath == "" {
		failIfErr(errors.New("--path must be specified"))
	}
	
	ctx := context.Background()
	idStore, err := identity.NewStore("enkit", defcon.Open)
	authInjector, err := newAuthInjector(idStore)
	failIfErr(err)
	tc := &tls.Config{
		RootCAs: x509.NewCertPool(),
		ClientAuth: tls.NoClientCert,
	}
	opts := append(authInjector.callOptions(), grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	conn, err := grpc.DialContext(ctx, *remoteAddr, opts...)
	failIfErr(err)
	capabilities := rpb.NewCapabilitiesClient(conn)
	cas := rpb.NewContentAddressableStorageClient(conn)
	rootState, err := os.Stat(*targetPath)
	failIfErr(err)
	if rootState.IsDir() {
		failIfErr(errors.New("Only files are supported"))
	}

	remoteCaps, err := capabilities.GetCapabilities(ctx, &rpb.GetCapabilitiesRequest{})
	failIfErr(err)

	text, err := prototext.Marshal(remoteCaps)
	failIfErr(err)
	fmt.Println(string(text))

	missing, err := cas.FindMissingBlobs(ctx, &rpb.FindMissingBlobsRequest{
		
	})

	failIfErr(err)
	for _, m := range missing.MissingBlobDigests {
		fmt.Println(m.Hash)
	}
}

type authInjector struct {
	token string
}

func newAuthInjector(idStore identity.IdentityStore) (*authInjector, error) {
	_, token, err := idStore.Load("")
	if err != nil {
		return nil, errors.Wrap(err, "reading token")
	}

	return &authInjector{
		token: token,
	}, nil
}

func (a *authInjector) unaryInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(ctx, method, req, reply, cc, a.optsWithAuth(opts)...)
	}
}

func (a *authInjector) streamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(ctx, desc, cc, method, a.optsWithAuth(opts)...)
	}
}

func (a *authInjector) callOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithStreamInterceptor(a.streamInterceptor()),
		grpc.WithUnaryInterceptor(a.unaryInterceptor()),
	}
}

func (a *authInjector) optsWithAuth(opts []grpc.CallOption) []grpc.CallOption {
	c := kcookie.New("Creds", a.token)
	return append(opts, grpc.Header(&metadata.MD{
		"cookie": []string{c.String()},
	}))
}

func newAuthUnaryInterceptor() (grpc.UnaryClientInterceptor, error){
	idStore, err := identity.NewStore("enkit", defcon.Open)
	if err != nil {
		return nil, errors.Wrap(err, "creating id store")
	}
	_, token, err := idStore.Load("")
	if err != nil {
		return nil, errors.Wrap(err, "loading token")
	}

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		opts = append(opts, grpc.Header(&metadata.MD{
			"cookie": []string{token},
		}))

		return invoker(ctx, method, req, reply, cc, opts...)
	}, nil
}

func failIfErr(err error) {
	if err != nil {
		fmt.Println("FATAL:", err)
		os.Exit(1)
	}
}
