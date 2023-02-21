package boundary

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/structs"
)

const (
	pluginName        = "boundary-driver-plugin"
	pluginVersion     = "v0.1.0"
	fingerprintPeriod = 30 * time.Second
	taskHandleVersion = 1
)

var (
	// pluginInfo describes the plugin
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     pluginVersion,
		Name:              pluginName,
	}

	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		//  Example schema
		//
		//	plugin "boundary-driver-plugin" {
		//		config {
		//			enabled        = true
		//			boundary_addr  = "http://127.0.0.1:9200"
		//			auth_method_id = "ampw_1234567890"
		//			org_id         = "o_1234567890"
		//			username       = "admin"
		//			password       = "password"
		//		}
		//	}
		"enabled": hclspec.NewDefault(
			hclspec.NewAttr("enabled", "bool", false),
			hclspec.NewLiteral("true"),
		),
		// enables / disables the plugin
		"boundary_addr": hclspec.NewDefault(
			hclspec.NewAttr("boundary_addr", "string", false),
			hclspec.NewLiteral(`"http://127.0.0.1:9200"`),
		),
		// address of the Boundary controller. This should optionally be set from
		// environment variables
		"auth_method": hclspec.NewDefault(
			hclspec.NewAttr("auth_method_id", "string", false),
			hclspec.NewLiteral("ampw_1234567890"),
		),
		// auth method to use for authentication. This should optionally be set from
		// environment variables. Must be either the name or ID
		"org": hclspec.NewDefault(
			hclspec.NewAttr("org_id", "string", false),
			hclspec.NewLiteral("o_1234567890"),
		),
		// org scope that the plugin with authenticate to. This should optionally be set from
		// environment variables. Must be either name or ID of scope
		"username": hclspec.NewDefault(
			hclspec.NewAttr("username", "string", false),
			hclspec.NewLiteral("admin"),
		),
		// username for the plugin to authenticate. This should optionally be set from
		// environment variables
		"password": hclspec.NewDefault(
			hclspec.NewAttr("password", "string", false),
			hclspec.NewLiteral("password"),
		),
		// password that the plugin will use to authenticate. This should optionally be set from
		// environment variables
		"default_groups": hclspec.NewAttr("default_groups", "[]string", false),
		// if default_groups is specified, will assign these groups permissions in boundary.
		// Must be either name or ID
		"default_project": hclspec.NewAttr("default_project_name", "string", false),
		// if default_project is specified, all generated resources will be created within that scope.
		// this can be overridden in the job file by specifying a project
	})

	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		// For the schema below a valid task would be:
		//   job "example" {
		//     group "example" {
		//       task "boundary" {
		//         driver = "boundary-driver-plugin"
		//         config {
		//           create_role 		 = true
		//			 create_host_catalog = true
		// 			 project_scope_id	 = "p_12345567890"
		// 			 credential_library {
		//			 	enabled 			= true
		// 				credential_store_id = ""
		//				path				= ""
		//         }
		//       }
		//     }
		//   }
		"create_role": hclspec.NewDefault(
			hclspec.NewAttr("create_role", "bool", false),
			hclspec.NewLiteral("false"),
		),
		// If create_role is set to true, A role will be created with the same
		// name as the job and with the following grant_strings:
		// "id=<id>;actions=authorize-session"
		"create_host_catalog": hclspec.NewDefault(
			hclspec.NewAttr("create_host_catalog", "bool", false),
			hclspec.NewLiteral("true"),
		),
		// If create_host_catalog is set to true, it will create a host catalog,
		// a host set and a host, all named the same as the job. If set to false,
		// an existing host catalog ID will need to be provided, within which
		// a new host set and host will be created, also named the same as the job
		"host_catalog": hclspec.NewAttr("host_catalog_id", "string", false),
		// host_catalog must be provided if create_host_catalog is set to false.
		// Must be either ID or name of existing host catalog
		"project_scope": hclspec.NewAttr("project_scope_id", "string", true),
		// project_scope is the scope where all resources related to the job are created.
		// this override the default_project set in the agent config
		"disable_default_groups": hclspec.NewDefault(
			hclspec.NewAttr("disable_default_groups", "bool", false),
			hclspec.NewLiteral("false"),
		),
		// this is an override that prevents default groups from being assigned permissions to this job
		"credential_library": hclspec.NewObject(map[string]*hclspec.Spec{
			"enabled": hclspec.NewDefault(
				hclspec.NewAttr("enabled", "bool", false),
				hclspec.NewLiteral("false"),
			),
			// If enabled is set to true, it will create a credential library for the target
			// using the rest of the configuartion parameters below and attach to the target
			"credential_store": hclspec.NewDefault(
				hclspec.NewAttr("credential_store_id", "string", false),
				hclspec.NewLiteral(""),
			),
			// credential_store_id where the credential library will be created must be supplied
			// when enabled is set to true. Must be either ID or name of existing credential store
			"path": hclspec.NewDefault(
				hclspec.NewAttr("path", "string", false),
				hclspec.NewLiteral(""),
			),
			// path in Vault to read  credentials from. Must be supplied if enabled is set to true
			"http_method": hclspec.NewDefault(
				hclspec.NewAttr("http_method", "string", false),
				hclspec.NewLiteral("GET"),
			),
			// http_method can either be GET or POST. If not supplied, it will use GET as the default method
			"http_request_body": hclspec.NewAttr("http_request_body", "string", false),
			// The body of the HTTP request the library sends to Vault when requesting credentials.
			// Only valid if http_method is set to POST
		}),
	})

	// capabilities indicates what optional features this driver supports
	// this should be set according to the target run time.
	capabilities = &drivers.Capabilities{
		// The plugin's capabilities signal Nomad which extra functionalities
		// are supported. For a list of available options check the docs page:
		// https://godoc.org/github.com/hashicorp/nomad/plugins/drivers#Capabilities
		SendSignals: true,
		Exec:        false,
	}
)

// Config contains configuration information for the plugin
type Config struct {
	Enabled        bool     `codec:"enabled"`
	BoundaryAddr   string   `codec:"boundary_addr"`
	AuthMethod     string   `codec:"auth_method"`
	Org            string   `codec:"org"`
	Username       string   `codec:"username"`
	Password       string   `codec:"password"`
	DefaultGroups  []string `codec:"default_groups"`
	DefaultProject string   `codec:"default_project"`
}

// TaskConfig contains configuration information for a task that runs with
// this plugin
type TaskConfig struct {
	CreateRole           bool         `codec:"create_role"`
	CreateHostCatalog    bool         `codec:"create_host_catalog"`
	HostCatalog          string       `codec:"host_catalog"`
	ProjectScope         string       `codec:"project_scope"`
	DisableDefaultGroups bool         `codec:"disable_default_groups"`
	CredentialLibrary    CredsLibrary `codec:"credential_library"`
}

type CredsLibrary struct {
	Enabled         bool   `codec:"enabled"`
	CredentialStore string `codec:"credential_store"`
	Path            string `codec:"path"`
	HttpMethod      string `codec:"http_method"`
	HttpRequestBody string `codec:"http_request_body"`
}

// TaskState is the runtime state which is encoded in the handle returned to
// Nomad client.
// This information is needed to rebuild the task state and handler during
// recovery.
type TaskState struct {
	ReattachConfig *structs.ReattachConfig
	TaskConfig     *drivers.TaskConfig
	StartedAt      time.Time

	TargetIds           []string
	RoleId              string
	HostCatalogId       string
	HostSetId           string
	HostId              string
	CredentialLibraryId string
}

// BoundaryDriverPlugin is an example driver plugin. When provisioned in a job,
// the taks will output a greet specified by the user.
type BoundaryDriverPlugin struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the plugin configuration set by the SetConfig RPC
	config *Config

	// nomadConfig is the client config from Nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in memory datastore mapping taskIDs to driver handles
	tasks *taskStore

	// ctx is the context for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// signalShutdown is called when the driver is shutting down and cancels
	// the ctx passed to any subsystems
	signalShutdown context.CancelFunc

	// logger will log to the Nomad agent
	logger hclog.Logger
}

// NewPlugin returns a new example driver plugin
func NewPlugin(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)

	return &BoundaryDriverPlugin{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &Config{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

// PluginInfo returns information describing the plugin.
func (d *BoundaryDriverPlugin) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the plugin configuration schema.
func (d *BoundaryDriverPlugin) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

// SetConfig is called by the client to pass the configuration for the plugin.
func (d *BoundaryDriverPlugin) SetConfig(cfg *base.Config) error {
	var config Config
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	// Save the configuration to the plugin
	d.config = &config

	// TODO: parse and validated any configuration value if necessary.
	//
	// If your driver agent configuration requires any complex validation
	// (some dependency between attributes) or special data parsing (the
	// string "10s" into a time.Interval) you can do it here and update the
	// value in d.config.
	//
	// In the example below we check if the shell specified by the user is
	// supported by the plugin.
	//shell := d.config.Shell
	//if shell != "bash" && shell != "fish" {
	//	return fmt.Errorf("invalid shell %s", d.config.Shell)
	//}

	// Save the Nomad agent configuration
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	// TODO: initialize any extra requirements if necessary.
	//
	// Here you can use the config values to initialize any resources that are
	// shared by all tasks that use this driver, such as a daemon process.

	return nil
}

// TaskConfigSchema returns the HCL schema for the configuration of a task.
func (d *BoundaryDriverPlugin) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

// Capabilities returns the features supported by the driver.
func (d *BoundaryDriverPlugin) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

// Fingerprint returns a channel that will be used to send health information
// and other driver specific node attributes.
func (d *BoundaryDriverPlugin) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

// handleFingerprint manages the channel and the flow of fingerprint data.
func (d *BoundaryDriverPlugin) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)

	// Nomad expects the initial fingerprint to be sent immediately
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// after the initial fingerprint we can set the proper fingerprint
			// period
			ticker.Reset(fingerprintPeriod)
			ch <- d.buildFingerprint()
		}
	}
}

// buildFingerprint returns the driver's fingerprint data
func (d *BoundaryDriverPlugin) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes:        map[string]*structs.Attribute{},
		Health:            drivers.HealthStateHealthy,
		HealthDescription: drivers.DriverHealthy,
	}

	// TODO: implement fingerprinting logic to populate health and driver
	// attributes.
	//
	// Fingerprinting is used by the plugin to relay two important information
	// to Nomad: health state and node attributes.
	//
	// If the plugin reports to be unhealthy, or doesn't send any fingerprint
	// data in the expected interval of time, Nomad will restart it.
	//
	// Node attributes can be used to report any relevant information about
	// the node in which the plugin is running (specific library availability,
	// installed versions of a software etc.). These attributes can then be
	// used by an operator to set job constrains.
	//
	// In the example below we check if the shell specified by the user exists
	// in the node.
	shell := d.config.Shell

	cmd := exec.Command("which", shell)
	if err := cmd.Run(); err != nil {
		return &drivers.Fingerprint{
			Health:            drivers.HealthStateUndetected,
			HealthDescription: fmt.Sprintf("shell %s not found", shell),
		}
	}

	// We also set the shell and its version as attributes
	cmd = exec.Command(shell, "--version")
	if out, err := cmd.Output(); err != nil {
		d.logger.Warn("failed to find shell version: %v", err)
	} else {
		re := regexp.MustCompile("[0-9]\\.[0-9]\\.[0-9]")
		version := re.FindString(string(out))

		fp.Attributes["driver.hello.shell_version"] = structs.NewStringAttribute(version)
		fp.Attributes["driver.hello.shell"] = structs.NewStringAttribute(shell)
	}

	return fp
}

// StartTask returns a task handle and a driver network if necessary.
func (d *BoundaryDriverPlugin) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var driverConfig TaskConfig
	if err := cfg.DecodeDriverConfig(&driverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	d.logger.Info("starting task", "driver_cfg", hclog.Fmt("%+v", driverConfig))
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	// TODO: implement driver specific mechanism to start the task.
	//
	// Once the task is started you will need to store any relevant runtime
	// information in a taskHandle and TaskState. The taskHandle will be
	// stored in-memory in the plugin and will be used to interact with the
	// task.
	//
	// The TaskState will be returned to the Nomad client inside a
	// drivers.TaskHandle instance. This TaskHandle will be sent back to plugin
	// if the task ever needs to be recovered, so the TaskState should contain
	// enough information to handle that.
	//
	// In the example below we use an executor to fork a process to run our
	// greeter. The executor is then stored in the handle so we can access it
	// later and the the plugin.Client is used to generate a reattach
	// configuration that can be used to recover communication with the task.
	executorConfig := &executor.ExecutorConfig{
		LogFile:  filepath.Join(cfg.TaskDir().Dir, "executor.out"),
		LogLevel: "debug",
	}

	exec, pluginClient, err := executor.CreateExecutor(d.logger, d.nomadConfig, executorConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create executor: %v", err)
	}

	echoCmd := fmt.Sprintf(`echo "%s"`, driverConfig.Greeting)
	execCmd := &executor.ExecCommand{
		Cmd:        d.config.Shell,
		Args:       []string{"-c", echoCmd},
		StdoutPath: cfg.StdoutPath,
		StderrPath: cfg.StderrPath,
	}

	ps, err := exec.Launch(execCmd)
	if err != nil {
		pluginClient.Kill()
		return nil, nil, fmt.Errorf("failed to launch command with executor: %v", err)
	}

	h := &taskHandle{
		exec:         exec,
		pid:          ps.Pid,
		pluginClient: pluginClient,
		taskConfig:   cfg,
		procState:    drivers.TaskStateRunning,
		startedAt:    time.Now().Round(time.Millisecond),
		logger:       d.logger,
	}

	driverState := TaskState{
		ReattachConfig: structs.ReattachConfigFromGoPlugin(pluginClient.ReattachConfig()),
		Pid:            ps.Pid,
		TaskConfig:     cfg,
		StartedAt:      h.startedAt,
	}

	if err := handle.SetDriverState(&driverState); err != nil {
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)
	go h.run()
	return handle, nil, nil
}

// RecoverTask recreates the in-memory state of a task from a TaskHandle.
func (d *BoundaryDriverPlugin) RecoverTask(handle *drivers.TaskHandle) error {
	if handle == nil {
		return errors.New("error: handle cannot be nil")
	}

	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	var driverConfig TaskConfig
	if err := taskState.TaskConfig.DecodeDriverConfig(&driverConfig); err != nil {
		return fmt.Errorf("failed to decode driver config: %v", err)
	}

	// TODO: implement driver specific logic to recover a task.
	//
	// Recovering a task involves recreating and storing a taskHandle as if the
	// task was just started.
	//
	// In the example below we use the executor to re-attach to the process
	// that was created when the task first started.
	plugRC, err := structs.ReattachConfigToGoPlugin(taskState.ReattachConfig)
	if err != nil {
		return fmt.Errorf("failed to build ReattachConfig from taskConfig state: %v", err)
	}

	execImpl, pluginClient, err := executor.ReattachToExecutor(plugRC, d.logger)
	if err != nil {
		return fmt.Errorf("failed to reattach to executor: %v", err)
	}

	h := &taskHandle{
		exec:         execImpl,
		pid:          taskState.Pid,
		pluginClient: pluginClient,
		taskConfig:   taskState.TaskConfig,
		procState:    drivers.TaskStateRunning,
		startedAt:    taskState.StartedAt,
		exitResult:   &drivers.ExitResult{},
	}

	d.tasks.Set(taskState.TaskConfig.ID, h)

	go h.run()
	return nil
}

// WaitTask returns a channel used to notify Nomad when a task exits.
func (d *BoundaryDriverPlugin) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)
	return ch, nil
}

func (d *BoundaryDriverPlugin) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)
	var result *drivers.ExitResult

	// TODO: implement driver specific logic to notify Nomad the task has been
	// completed and what was the exit result.
	//
	// When a result is sent in the result channel Nomad will stop the task and
	// emit an event that an operator can use to get an insight on why the task
	// stopped.
	//
	// In the example below we block and wait until the executor finishes
	// running, at which point we send the exit code and signal in the result
	// channel.
	ps, err := handle.exec.Wait(ctx)
	if err != nil {
		result = &drivers.ExitResult{
			Err: fmt.Errorf("executor: error waiting on process: %v", err),
		}
	} else {
		result = &drivers.ExitResult{
			ExitCode: ps.ExitCode,
			Signal:   ps.Signal,
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case ch <- result:
		}
	}
}

// StopTask stops a running task with the given signal and within the timeout window.
func (d *BoundaryDriverPlugin) StopTask(taskID string, timeout time.Duration, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific logic to stop a task.
	//
	// The StopTask function is expected to stop a running task by sending the
	// given signal to it. If the task does not stop during the given timeout,
	// the driver must forcefully kill the task.
	//
	// In the example below we let the executor handle the task shutdown
	// process for us, but you might need to customize this for your own
	// implementation.
	if err := handle.exec.Shutdown(signal, timeout); err != nil {
		if handle.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("executor Shutdown failed: %v", err)
	}

	return nil
}

// DestroyTask cleans up and removes a task that has terminated.
func (d *BoundaryDriverPlugin) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.IsRunning() && !force {
		return errors.New("cannot destroy running task")
	}

	// TODO: implement driver specific logic to destroy a complete task.
	//
	// Destroying a task includes removing any resources used by task and any
	// local references in the plugin. If force is set to true the task should
	// be destroyed even if it's currently running.
	//
	// In the example below we use the executor to force shutdown the task
	// (timeout equals 0).
	if !handle.pluginClient.Exited() {
		if err := handle.exec.Shutdown("", 0); err != nil {
			handle.logger.Error("destroying executor failed", "err", err)
		}

		handle.pluginClient.Kill()
	}

	d.tasks.Delete(taskID)
	return nil
}

// InspectTask returns detailed status information for the referenced taskID.
func (d *BoundaryDriverPlugin) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return handle.TaskStatus(), nil
}

// TaskStats returns a channel which the driver should send stats to at the given interval.
func (d *BoundaryDriverPlugin) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific logic to send task stats.
	//
	// This function returns a channel that Nomad will use to listen for task
	// stats (e.g., CPU and memory usage) in a given interval. It should send
	// stats until the context is canceled or the task stops running.
	//
	// In the example below we use the Stats function provided by the executor,
	// but you can build a set of functions similar to the fingerprint process.
	return handle.exec.Stats(ctx, interval)
}

// TaskEvents returns a channel that the plugin can use to emit task related events.
func (d *BoundaryDriverPlugin) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

// SignalTask forwards a signal to a task.
// This is an optional capability.
func (d *BoundaryDriverPlugin) SignalTask(taskID string, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// TODO: implement driver specific signal handling logic.
	//
	// The given signal must be forwarded to the target taskID. If this plugin
	// doesn't support receiving signals (capability SendSignals is set to
	// false) you can just return nil.
	sig := os.Interrupt
	if s, ok := signals.SignalLookup[signal]; ok {
		sig = s
	} else {
		d.logger.Warn("unknown signal to send to task, using SIGINT instead", "signal", signal, "task_id", handle.taskConfig.ID)

	}
	return handle.exec.Signal(sig)
}

// ExecTask returns the result of executing the given command inside a task.
// This is an optional capability.
func (d *BoundaryDriverPlugin) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	// TODO: implement driver specific logic to execute commands in a task.
	return nil, errors.New("This driver does not support exec")
}
