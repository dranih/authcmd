/*
This is an attempt to port the 'only' script from https://at.magma-soft.at/sw/blog/posts/The_Only_Way_For_SSH_Forced_Commands
The goal is to provide a way to control ssh access to a environnement with allowed/forbidden commands/arguments and replace.
*/
package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// authcmdConfig holds the configuration parsed from the authcmd.yml
// plus the cmdTags from the cmd arguments
type authcmdConfig struct {
	ShowTerseDenied *bool                     `yaml:"showTerseDenied"`
	ShowAllowed     *bool                     `yaml:"showAllowed"`
	ShowDenied      *bool                     `yaml:"showDenied"`
	ExpandEnvVars   *bool                     `yaml:"expandEnvVars"`
	EnableLogging   *bool                     `yaml:"enableLogging"`
	LogFile         string                    `yaml:"logFile"`
	UseShell        string                    `yaml:"useShell"`
	HelpText        string                    `yaml:"helpText"`
	SetEnvVars      map[string]string         `yaml:"setEnvVars"`
	AllowedCmd      []*cmd                    `yaml:"allowedCmd"`
	KeyTags         map[string]*authcmdConfig `yaml:"keyTags"`
	cmdTags         []string
}

// A cmd is the config detail of an allowed cmd from the authcmd.yml config file
type cmd struct {
	Command    string            `yaml:"command"`
	Args       *args             `yaml:"args"`
	Replace    map[string]string `yaml:"replace"`
	SetEnvVars map[string]string `yaml:"setEnvVars"`
	MustMatch  []string          `yaml:"mustMatch"`
}

// A args is the detail of the allowed and forbidden args of an allowed cmd
type args struct {
	Allowed   []string `yaml:"allowed"`
	Forbidden []string `yaml:"forbidden"`
}

// config var holds the loaded authcmdConfig from config file
var config *authcmdConfig

// logger is a global var for logging
var logger log.Logger

// Main function - entry point
func main() {
	ret, _ := handle()
	os.Exit(ret)
}

// handle function grabs the command passed to the ssh call from the SSH_ORIGINAL_COMMAND env var
// and calls the try function to return the return code and the output
// not in main for testing purpose
func handle() (int, string) {
	if err := loadConfig(); err != nil {
		msg := fmt.Sprintf("Could not load config file : %s\n", err.Error())
		fmt.Print(msg)
		return 2, msg
	}
	originalCmd, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	if !ok || len(originalCmd) <= 0 {
		return deny(fmt.Errorf("direct ssh not allowed, you must specify a command"))
	}
	parsedOriginalCmd, err := parseCommandLine(originalCmd)
	if err != nil {
		return deny(err)
	}
	originalArgs := strings.TrimPrefix(originalCmd, parsedOriginalCmd[0])

	for _, allowedCmd := range config.AllowedCmd {
		allowed := allowedCmd.Command
		// If allowed starts with / we want exact match
		if strings.HasPrefix(allowed, "/") {
			if allowed == parsedOriginalCmd[0] {
				return try(allowedCmd, originalArgs, parsedOriginalCmd[1:])
			}
			continue
		}

		// if original command starts with slash, we check if it is in the path.
		if strings.HasPrefix(parsedOriginalCmd[0], "/") {
			if allowedPath, err := exec.LookPath(allowed); err == nil {
				if allowedPath == parsedOriginalCmd[0] {
					return try(allowedCmd, originalArgs, parsedOriginalCmd[1:])
				}
				continue
			}
		}

		// both are relative paths or filenames
		if allowed == parsedOriginalCmd[0] {
			return try(allowedCmd, originalArgs, parsedOriginalCmd[1:])
		}
	}

	return deny(fmt.Errorf("command `%s` not allowed", parsedOriginalCmd[0]))
}

// loadConfig loads authcmd.yml file from
// env var AUTHCMD_CONFIG_FILE
// or ~/authcmd.yml
// or authcmd.yml
// using the keyTags passed as args
func loadConfig() error {
	config = &authcmdConfig{}
	configFile, ok := os.LookupEnv("AUTHCMD_CONFIG_FILE")
	if !ok || !fileExists(configFile) {
		userHomeDir, err := os.UserHomeDir()
		if err == nil && fileExists(filepath.Join(userHomeDir, "authcmd.yml")) {
			configFile = filepath.Join(userHomeDir, "authcmd.yml")
			ok = true
		} else {
			if fileExists("authcmd.yml") {
				configFile = "authcmd.yml"
				ok = true
			}
		}
	}

	if ok {
		yfile, err := ioutil.ReadFile(configFile)
		if err == nil {
			err = yaml.Unmarshal(yfile, &config)
		}
		if err != nil {
			return fmt.Errorf("cannot read config file `%s` got error `%s`", configFile, err.Error())
		}
	} else {
		return fmt.Errorf("did not found any config file")
	}

	config.cmdTags = os.Args[1:]
	// Merging config from keyTags
	if config.KeyTags != nil {
		for _, tag := range config.cmdTags {
			if tagConfig, exists := config.KeyTags[tag]; exists {
				config.mergeConfig(tagConfig)
			}
		}
	}

	if config.EnableLogging != nil && *config.EnableLogging {
		var err error
		var logFile *os.File
		if config.LogFile != "" {
			logFile, err = os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		}
		if config.LogFile == "" || err != nil {
			if userHomeDir, e := os.UserHomeDir(); e == nil {
				logFile, err = os.OpenFile(filepath.Join(userHomeDir, "authcmd.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			}
		}
		// If unable to open log file, no logging
		if err != nil || logFile == nil {
			*config.EnableLogging = false
		} else {
			logger.SetOutput(logFile)
			logger.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
		}
	}

	return nil
}

// mergeConfig merges the tagConfig *authcmdConfig in parameter
// *bool and string parameters are overrides if in the tagConfig
// Append allowedCmd if does not exists, append args options if it does
func (config *authcmdConfig) mergeConfig(tagConfig *authcmdConfig) {
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ authcmdConfig }{}))
	tc := reflect.Indirect(reflect.ValueOf(tagConfig))
	c := reflect.Indirect(reflect.ValueOf(config))

	for _, field := range fields {
		if !field.IsExported() {
			continue
		}
		switch field.Type {
		//Merging *bool and string parameters
		case reflect.TypeOf((*bool)(nil)), reflect.TypeOf((string)("")):
			tcbyname := tc.FieldByName(field.Name)
			cbyname := c.FieldByName(field.Name)
			if tcbyname.IsValid() && cbyname.IsValid() &&
				(tcbyname.Kind() == reflect.Ptr && !tcbyname.IsNil()) || (tcbyname.Kind() == reflect.String && !tcbyname.IsZero()) {
				if cbyname.CanSet() {
					cbyname.Set(tcbyname)
				}
			}
		//Merging map[string]string parameters
		case reflect.TypeOf((map[string]string)(nil)):
			tcbyname := tc.FieldByName(field.Name)
			cbyname := c.FieldByName(field.Name)
			if tcbyname.IsValid() && cbyname.IsValid() && !tcbyname.IsNil() {
				if cbyname.IsNil() {
					cbyname.Set(tcbyname)
				} else {
					iter := tcbyname.MapRange()
					for iter.Next() {
						cbyname.SetMapIndex(iter.Key(), iter.Value())
					}
				}
			}
		}
	}
	//Merging allowedCmd
	for _, tagCmd := range tagConfig.AllowedCmd {
		existsID := -1
		for i, existingCmd := range config.AllowedCmd {
			if tagCmd.Command == existingCmd.Command {
				existsID = i
			}
		}
		if existsID == -1 {
			config.AllowedCmd = append(config.AllowedCmd, tagCmd)
		} else if tagCmd.Args != nil {
			if config.AllowedCmd[existsID].Args == nil {
				config.AllowedCmd[existsID].Args = &args{}
			}
			if tagCmd.Args.Forbidden != nil && len(tagCmd.Args.Forbidden) > 0 {
				if config.AllowedCmd[existsID].Args.Forbidden == nil {
					config.AllowedCmd[existsID].Args.Forbidden = []string{}
				}
				config.AllowedCmd[existsID].Args.Forbidden = append(config.AllowedCmd[existsID].Args.Forbidden, tagCmd.Args.Forbidden...)
			}
			if tagCmd.Args.Allowed != nil && len(tagCmd.Args.Allowed) > 0 {
				if config.AllowedCmd[existsID].Args.Allowed == nil {
					config.AllowedCmd[existsID].Args.Allowed = []string{}
				}
				config.AllowedCmd[existsID].Args.Allowed = append(config.AllowedCmd[existsID].Args.Forbidden, tagCmd.Args.Allowed...)
			}
			for a, b := range tagCmd.Replace {
				config.AllowedCmd[existsID].Replace[a] = b
			}
			for a, b := range tagCmd.SetEnvVars {
				config.AllowedCmd[existsID].SetEnvVars[a] = b
			}
			config.AllowedCmd[existsID].MustMatch = append(config.AllowedCmd[existsID].MustMatch, tagCmd.MustMatch...)
		}
	}
}

// fileExists check if filepath exists as a file
func fileExists(filepath string) bool {
	fileinfo, err := os.Stat(filepath)
	if os.IsNotExist(err) {
		return false
	}
	return !fileinfo.IsDir()
}

// deny function formats the error output according to configuration
// and gives a 1 exit code
func deny(err error) (int, string) {
	logTags := ""
	if len(config.cmdTags) > 0 {
		logTags = fmt.Sprint(" tags `", strings.Join(config.cmdTags, ","), "`")
	}
	user, _ := user.Current()
	writeLog("WARN - Denied user `%s`%s error `%s`", user.Username, logTags, err.Error())
	var out string
	if config.ShowTerseDenied != nil && *config.ShowTerseDenied {
		out = "Denied\n"
	} else {
		if config.ShowDenied != nil && *config.ShowDenied {
			out = fmt.Sprintf("Denied : %s\n", err.Error())
		}
		if config.ShowAllowed != nil && *config.ShowAllowed {
			var allowedCmds []string
			for _, allowedCmd := range config.AllowedCmd {
				allowedCmds = append(allowedCmds, allowedCmd.Command)
			}
			out += fmt.Sprintf("Allowed : %s\n", strings.Join(allowedCmds, ","))
		}
		if config.HelpText != "" {
			out += fmt.Sprintln(config.HelpText)
		}
	}
	if len(out) > 0 {
		fmt.Print(out)
	}
	return 1, out
}

// try function goals is to check if the command passed in the ssh call is allowed and hence execute it
// it checks allowed and forbidden args and MustMatch regex for the whole command line to allow the command
// if allowed
// it executes replace regex
// it sets env vars
// it runs the command with go os/exec or the specified shell in config
// it return the return code and output
func try(allowedCmd *cmd, originalArgs string, originalArgsParsed []string) (int, string) {
	if allowedCmd.Args != nil {
		for _, args := range originalArgsParsed {
			if allowedCmd.Args.Forbidden != nil {
				for _, forbiddenRegex := range allowedCmd.Args.Forbidden {
					if matched, e := regexp.MatchString(forbiddenRegex, args); e == nil {
						if matched {
							return deny(fmt.Errorf("command `%s` argument : `%s` forbidden : regex `%s`", allowedCmd.Command, args, forbiddenRegex))
						}
					} else {
						writeLog("Unable to compile regex %s, got %s", forbiddenRegex, e.Error())
					}
				}
			}

			// if no allowed args, all is allowed
			if allowedCmd.Args.Allowed != nil {
				found := false
				for _, allowedRegex := range allowedCmd.Args.Allowed {
					if matched, e := regexp.MatchString(allowedRegex, args); e == nil {
						if matched {
							found = matched
							break
						}
					} else {
						writeLog("Unable to compile regex %s, got %s", allowedRegex, e.Error())
					}
				}
				if !found {
					return deny(fmt.Errorf("command `%s` arguments : `%s` not allowed", allowedCmd.Command, args))
				}
			}
		}
	}
	for _, mustMatch := range allowedCmd.MustMatch {
		if matched, e := regexp.MatchString(mustMatch, originalArgs); e == nil {
			if !matched {
				return deny(fmt.Errorf("command `%s` arguments : `%s` not matching regex `%s`", allowedCmd.Command, originalArgs, mustMatch))
			}
		} else {
			writeLog("Unable to compile regex %s, got %s", mustMatch, e.Error())
		}
	}
	for search, replace := range allowedCmd.Replace {
		if re, e := regexp.Compile(search); e == nil {
			originalArgs = re.ReplaceAllString(originalArgs, replace)
		} else {
			writeLog("Unable to compile regex %s, got %s", search, e.Error())
		}
	}
	config.setEnvVars(allowedCmd)
	if config.ExpandEnvVars != nil && *config.ExpandEnvVars {
		originalArgs = os.ExpandEnv(originalArgs)
	}
	var cmd *exec.Cmd
	if config.UseShell != "" {
		if config.UseShell == "default" {
			if shell, ok := os.LookupEnv("SHELL"); ok {
				config.UseShell = shell
			}
		}
		if shellPath, err := exec.LookPath(config.UseShell); err == nil {
			cmd = exec.Command(shellPath, "-c", allowedCmd.Command+" "+originalArgs)
		} else {
			return deny(fmt.Errorf("did not found shell `%s` in path : `%s`", config.UseShell, err.Error()))
		}
	} else {
		if newParsedCmd, e := parseCommandLine(allowedCmd.Command + " " + originalArgs); e == nil {
			cmd = exec.Command(allowedCmd.Command, newParsedCmd[1:]...)
		} else {
			return deny(fmt.Errorf("unable to parse arguments `%s` : `%s`", originalArgs, e.Error()))
		}

	}
	user, _ := user.Current()
	logTags := ""
	if len(config.cmdTags) > 0 {
		logTags = fmt.Sprint(" tags `", strings.Join(config.cmdTags, ","), "`")
	}

	var buffer bytes.Buffer
	mwriter := io.MultiWriter(&buffer, os.Stdout)
	cmd.Stdout = mwriter
	cmd.Stderr = mwriter

	writeLog("RUNNING - user `%s`%s command `%s`", user.Username, logTags, cmd.String())
	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), buffer.String()
		}
		return 1, buffer.String()
	}
	return 0, buffer.String()
}

// writeLog write msg with args to logger if logging enabled
func writeLog(msg string, args ...interface{}) {
	if config.EnableLogging != nil && *config.EnableLogging {
		logger.Printf(msg, args...)
	}
}

// setEnvVars sets env vars from config
func (config *authcmdConfig) setEnvVars(allowedCmd *cmd) {
	for envVar, value := range config.SetEnvVars {
		os.Setenv(envVar, value)
	}
	for envVar, value := range allowedCmd.SetEnvVars {
		os.Setenv(envVar, value)
	}
}

// parseCommandLine function returns a string slice of command line arguments from a full command line string
// From https://stackoverflow.com/questions/34118732/parse-a-command-line-string-into-flags-and-arguments-in-golang
// Should better use https://github.com/google/shlex ?
func parseCommandLine(command string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for _, c := range command {

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, fmt.Errorf(fmt.Sprintf("unclosed quote in command line: %s", command))
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}
