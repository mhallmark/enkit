package main

import (
	"github.com/enfabrica/enkit/lib/kflags/kcobra"
	"github.com/enfabrica/enkit/lib/khttp"
	"github.com/enfabrica/enkit/lib/logger"
	"github.com/enfabrica/enkit/lib/oauth"
	"github.com/enfabrica/enkit/lib/srand"
	"github.com/enfabrica/enkit/proxy/httpp"
	"github.com/enfabrica/enkit/proxy/nasshp"
	"github.com/spf13/cobra"
	"log"
	"math/rand"
	"net/http"
)

type Dumper struct {
	Real http.Handler
	Log  logger.Printer
}

func (d *Dumper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.Log("REQUEST %s", r.Method)
	d.Log(" - host %s", r.Host)
	d.Log(" - url %s", r.URL)
	d.Log(" - headers")
	for key, value := range r.Header {
		d.Log("   - %s: %s", key, value)
	}
	d.Real.ServeHTTP(w, r)
}

func main() {
	root := &cobra.Command{
		Use:           "proxy",
		Long:          `proxy - starts an authenticating proxy`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Example: `  $ proxy -c ./mappings.toml
	To start a proxy mapping the urls defined in mappings.toml.`,
	}

	set := &kcobra.FlagSet{FlagSet: root.Flags()}

	pflags := httpp.DefaultFlags()
	pflags.Register(set, "")

	hflags := khttp.DefaultFlags()
	hflags.Register(set, "")

	rflags := oauth.DefaultRedirectorFlags()
	rflags.Register(set, "")

	nflags := nasshp.DefaultFlags()
	nflags.Register(set, "")

	unsafeDevelopmentMode := false
	root.Flags().BoolVar(&unsafeDevelopmentMode, "unsafe-development-mode", false,
		"Disable oauth ssh based authentication - this is for testing only!")

	mylog := logger.Nil
	root.RunE = func(cmd *cobra.Command, args []string) error {
		var authenticate oauth.Authenticate
		if rflags.AuthURL != "" {
			redirector, err := oauth.NewRedirector(oauth.WithRedirectorFlags(rflags))
			if err != nil {
				return err
			}
			authenticate = redirector.Authenticate
		}

		hproxy, err := httpp.New(httpp.FromFlags(pflags), httpp.WithAuthenticator(authenticate), httpp.WithLogging(mylog))
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		mux.Handle("/", hproxy)
		if authenticate == nil {
			mylog.Warnf("ssh gateway disabled as no authentication was configured")
		} else {
			if unsafeDevelopmentMode {
				mylog.Errorf("Watch out! The proxy is being started with unsafe authentication mode! No authentication performed")
				authenticate = nil
			}

			rng := rand.New(srand.Source)
			nasshp, err := nasshp.New(rng, authenticate, nasshp.FromFlags(nflags), nasshp.WithLogging(mylog))
			if err != nil {
				return err
			}
			nasshp.Register(mux.HandleFunc)
		}

		server, err := khttp.FromFlags(hflags)
		if err != nil {
			return err
		}

		return server.Run(mylog.Infof, &Dumper{Real: mux, Log: log.Printf}, hproxy.Domains...)
	}

	kcobra.RunWithDefaults(root, nil, &mylog)
}
