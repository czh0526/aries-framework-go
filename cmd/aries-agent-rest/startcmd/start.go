package startcmd

import (
	"errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/component/storage/mysql"
	"github.com/czh0526/aries-framework-go/pkg/controller"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries"
	"github.com/czh0526/aries-framework-go/pkg/framework/context"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	agentHostEnvKey        = "ARIES_API_HOST"
	agentHostFlagName      = "api-host"
	agentHostFlagShorthand = "a"
	agentHostFlagUsage     = "Host Name:Port. Alternatively, this can be set with the following environment variable: " + agentHostEnvKey

	databaseTypeEnvKey        = "ARIES_DATABASE_TYPE"
	databaseTypeFlagName      = "database-type"
	databaseTypeFlagShorthand = "q"
	databaseTypeFlagUsage     = "Supported options: mem, leveldb, couchdb, mongodb, mysql, postgresql. " +
		" Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databasePrefixEnvKey        = "ARIES_DATABASE_PREFIX"
	databasePrefixFlagName      = "database-prefix"
	databasePrefixFlagShorthand = "u"
	databasePrefixFlagUsage     = "Also you can use this variable for paths or connection strings as needed. " +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	databaseTimeoutEnvKey    = "ARIES_DATABASE_TIMEOUT"
	databaseTimeoutFlagName  = "database-timeout"
	databaseTimeoutFlagUsage = " Default: " + databaseTimeoutDefault + " seconds." +
		" Alternatively, this can be set with the following environment variable: " + databaseTimeoutEnvKey
	databaseTimeoutDefault = "30"

	databaseTypeMemOption   = "mem"
	databaseTypeMySQLOption = "mysql"
)

var (
	errMissingHost = errors.New("host not provided")
	logger         = log.New("aries-framework/agent-rest")

	keyTypes = map[string]spikms.KeyType{
		"ed25519":           spikms.ED25519Type,
		"ecdsap256ieee1363": spikms.ECDSAP256IEEEP1363,
		"ecdsap256der":      spikms.ECDSAP256DER,
	}

	keyAgreementTypes = map[string]spikms.KeyType{
		"x25519kw": spikms.X25519ECDHKWType,
		"p256kw":   spikms.NISTP256ECDHKWType,
	}
)

var supportedStorageProviders = map[string]func(prefix string) (spistorage.Provider, error){
	//databaseTypeMemOption: func(_ string) (spistorage.Provider, error) {
	//	return mem.NewProvider(), nil
	//},
	databaseTypeMySQLOption: func(path string) (spistorage.Provider, error) {
		return mysql.NewProvider(path)
	},
}

type server interface {
	ListenAndServe(host string, router http.Handler, certFile, keyFile string) error
}

type HTTPServer struct{}

func (s *HTTPServer) ListenAndServe(host string, router http.Handler, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

func Cmd(server server) (*cobra.Command, error) {
	startCmd := createStartCMD(server)

	return startCmd, nil
}

func createStartCMD(server server) *cobra.Command {
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Starts an agent",
		Long:  "Starts an Aries agent controller",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := NewAgentParameters(server, cmd)
			if err != nil {
				return err
			}

			return startAgent(parameters)
		},
	}

	createFlags(startCmd)

	return startCmd
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(agentHostFlagName, agentHostFlagShorthand, "", agentHostFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
}

type AgentParameters struct {
	server  server
	host    string
	dbParam *dbParam
}

type dbParam struct {
	dbType  string
	prefix  string
	timeout uint64
}

func (params *AgentParameters) NewRouter() (*mux.Router, error) {
	if params.host == "" {
		return nil, errMissingHost
	}

	ctx, err := createAriesAgent(params)
	if err != nil {
		return nil, err
	}

	handlers, err := controller.GetRestHandlers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start aries agent rest on port [%s], "+
			"failed to get rest service api: %w", params.host, err)
	}

	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return router, nil
}

func createStoreProviders(params *AgentParameters) (spistorage.Provider, error) {
	provider, supported := supportedStorageProviders[params.dbParam.dbType]
	if !supported {
		return nil, fmt.Errorf("key database type not set to a valid type")
	}

	var store spistorage.Provider

	err := backoff.RetryNotify(
		func() error {
			var err error
			store, err = provider(params.dbParam.prefix)
			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), params.dbParam.timeout),
		func(err error, d time.Duration) {
			logger.Warnf("failed to connect to storage, will sleep for %s before trying again: %s\n",
				d, err)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to storage at %s: %w", params.dbParam.prefix, err)
	}

	return store, nil
}

func createAriesAgent(params *AgentParameters) (*context.Context, error) {
	var opts []aries.Option

	storePro, err := createStoreProviders(params)
	if err != nil {
		return nil, err
	}

	opts = append(opts, aries.WithStoreProvider(storePro))

	framework, err := aries.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create aries agent: %w", err)
	}

	ctx, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to create aries agent: %w", err)
	}

	return ctx, nil
}

func NewAgentParameters(server server, cmd *cobra.Command) (*AgentParameters, error) {
	host, err := getUserSetVar(cmd, agentHostFlagName, agentHostEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbParam, err := getDBParam(cmd)
	if err != nil {
		return nil, err
	}

	parameters := &AgentParameters{
		server:  server,
		host:    host,
		dbParam: dbParam,
	}

	return parameters, nil
}

func getUserSetVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	if cmd != nil && cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf("flag not found: %s", err)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)
	if isOptional || isSet {
		return value, nil
	}

	return "", fmt.Errorf(" Neither %s(command lint flag) nor %s(environment variable) have been set.", flagName, envKey)
}

func getDBParam(cmd *cobra.Command) (*dbParam, error) {
	dbParam := &dbParam{}

	var err error

	dbParam.dbType, err = getUserSetVar(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	dbParam.prefix, err = getUserSetVar(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	dbTimeout, err := getUserSetVar(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey, true)
	if err != nil {
		return nil, err
	}

	if dbTimeout == "" || dbTimeout == "0" {
		dbTimeout = databaseTimeoutDefault
	}

	t, err := strconv.Atoi(dbTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse db timeout %s: %w", dbTimeout, err)
	}

	dbParam.timeout = uint64(t)
	return dbParam, nil
}

func startAgent(params *AgentParameters) error {
	logger.Infof("Starting aries agent rest on host [%s]", params.host)

	router, err := params.NewRouter()
	if err != nil {
		return err
	}

	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodHead},
			AllowedHeaders: []string{"Origin", "Accept", "X-Requested-With", "Authorization", "Content-Type"},
		},
	).Handler(router)

	err = params.server.ListenAndServe(params.host, handler, "", "")
	if err != nil {
		return err
	}

	return nil
}
