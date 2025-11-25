package startcmd

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/controller"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"strconv"
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

type server interface {
	ListenAndServe(host string, router http.Handler, certFile, keyFile string) error
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

	handlers, err := controller.GetHandlers(params.server)

	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return router, nil
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

func startAgent(parameters *AgentParameters) error {
	logger.Infof("Starting aries agent rest on host [%s]", parameters.host)

	router, err := parameters.NewRouter()
	return nil
}
