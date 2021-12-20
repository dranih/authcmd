package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Show_terse_denied *bool
	Show_allowed      *bool
	Show_denied       *bool
	Expand_env_vars   *bool
	Enable_logging    *bool
	Log_file          string
	Use_shell         string
	Help_text         string
	Allowed_cmd       []*cmd
	Key_tags          map[string]*Config
	cmd_tags          []string
}

type cmd struct {
	Command string
	Args    *args
}

type args struct {
	Allowed   []string
	Forbidden []string
	Replace   map[string]string
}

var config *Config
var logger log.Logger

// https://at.magma-soft.at/sw/blog/posts/The_Only_Way_For_SSH_Forced_Commands/
func main() {
	ret, output := handle()
	fmt.Print(output)
	os.Exit(ret)
}

func handle() (int, string) {
	if err := loadConfig(); err != nil {
		return 2, fmt.Sprintf("Could not load config file : %s\n", err.Error())
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

	for _, allowedCmd := range config.Allowed_cmd {
		allowed := allowedCmd.Command
		// If allowed starts with / we want exact match
		if strings.HasPrefix(allowed, "/") {
			if allowed == parsedOriginalCmd[0] {
				return try(allowedCmd, originalArgs)
			} else {
				continue
			}
		}

		// if original command starts with slash, we check if it is in the path.
		if strings.HasPrefix(parsedOriginalCmd[0], "/") {
			if allowedPath, err := exec.LookPath(allowed); err == nil {
				if allowedPath == parsedOriginalCmd[0] {
					return try(allowedCmd, originalArgs)
				} else {
					continue
				}
			}
		}

		// both are relative paths or filenames
		if allowed == parsedOriginalCmd[0] {
			return try(allowedCmd, originalArgs)
		}
	}

	return deny(fmt.Errorf("command `%s` not allowed", parsedOriginalCmd[0]))
}

// loadConfig load authcmd.yml file from
// env var AUTHCMD_CONFIG_FILE
// or ~/authcmd.yml
// or authcmd.yml
// and merge allowed command from args
func loadConfig() error {
	config = &Config{}
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

	config.cmd_tags = os.Args[1:]
	// Merging config from key_tags
	if config.Key_tags != nil {
		cmd_tags_map := map[string]bool{}
		for _, tag := range config.cmd_tags {
			cmd_tags_map[tag] = true
		}
		for tag, tagConfig := range config.Key_tags {
			if cmd_tags_map[tag] {
				config.mergeConfig(tagConfig)
			}
		}
	}

	if config.Enable_logging != nil && *config.Enable_logging {
		var err error
		var logFile *os.File
		if config.Log_file != "" {
			logFile, err = os.OpenFile(config.Log_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		}
		if config.Log_file == "" || err != nil {
			if userHomeDir, e := os.UserHomeDir(); e == nil {
				logFile, err = os.OpenFile(filepath.Join(userHomeDir, "authcmd.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			}
		}
		// If unable to open log file, no logging
		if err != nil || logFile == nil {
			*config.Enable_logging = false
		} else {
			logger.SetOutput(logFile)
			logger.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
		}
	}

	return nil
}

// mergeConfig merges the tagConfig *Config in parameter
// *bool and string parameters are overrides if in the tagConfig
// Append allowed_cmd if does not exists, append args options if it does
func (config *Config) mergeConfig(tagConfig *Config) {
	fields := reflect.VisibleFields(reflect.TypeOf(struct{ Config }{}))
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
		}
	}
	//Merging allowed_cmd
	for _, tagCmd := range tagConfig.Allowed_cmd {
		existsId := -1
		for i, existingCmd := range config.Allowed_cmd {
			if tagCmd.Command == existingCmd.Command {
				existsId = i
			}
		}
		if existsId == -1 {
			config.Allowed_cmd = append(config.Allowed_cmd, tagCmd)
		} else if tagCmd.Args != nil {
			if config.Allowed_cmd[existsId].Args == nil {
				config.Allowed_cmd[existsId].Args = &args{}
			}
			if tagCmd.Args.Forbidden != nil && len(tagCmd.Args.Forbidden) > 0 {
				if config.Allowed_cmd[existsId].Args.Forbidden == nil {
					config.Allowed_cmd[existsId].Args.Forbidden = []string{}
				}
				config.Allowed_cmd[existsId].Args.Forbidden = append(config.Allowed_cmd[existsId].Args.Forbidden, tagCmd.Args.Forbidden...)
			}
			if tagCmd.Args.Allowed != nil && len(tagCmd.Args.Allowed) > 0 {
				if config.Allowed_cmd[existsId].Args.Allowed == nil {
					config.Allowed_cmd[existsId].Args.Allowed = []string{}
				}
				config.Allowed_cmd[existsId].Args.Allowed = append(config.Allowed_cmd[existsId].Args.Forbidden, tagCmd.Args.Allowed...)
			}
			for a, b := range tagCmd.Args.Replace {
				config.Allowed_cmd[existsId].Args.Replace[a] = b
			}
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

func deny(err error) (int, string) {
	logTags := ""
	if len(config.cmd_tags) > 0 {
		logTags = fmt.Sprint(" tags `", strings.Join(config.cmd_tags, ","), "`")
	}
	user, _ := user.Current()
	writeLog("WARN - Denied user `%s`%s error `%s`", user.Username, logTags, err.Error())
	var out string
	if config.Show_terse_denied != nil && *config.Show_terse_denied {
		out = "Denied\n"
	} else {
		if config.Show_denied != nil && *config.Show_denied {
			out = fmt.Sprintf("Denied : %s\n", err.Error())
		}
		if config.Show_allowed != nil && *config.Show_allowed {
			var allowedCmds []string
			for _, allowedCmd := range config.Allowed_cmd {
				allowedCmds = append(allowedCmds, allowedCmd.Command)
			}
			out += fmt.Sprintf("Allowed : %s\n", strings.Join(allowedCmds, ","))
		}
		if config.Help_text != "" {
			out += fmt.Sprintln(config.Help_text)
		}
	}
	return 1, out
}

func try(allowedCmd *cmd, originalArgs string) (int, string) {
	if allowedCmd.Args != nil {
		for _, forbiddenRegex := range allowedCmd.Args.Forbidden {
			if matched, e := regexp.MatchString(forbiddenRegex, originalArgs); e == nil {
				if matched {
					return deny(fmt.Errorf("command `%s` arguments : `%s` forbidden : regex `%s`", allowedCmd.Command, originalArgs, forbiddenRegex))
				}
			} else {
				writeLog("Unable to compile regex %s, got %s", forbiddenRegex, e.Error())
			}
		}
		// if no allowed args, all is allowed
		if len(allowedCmd.Args.Allowed) > 0 {
			found := false
			for _, allowedRegex := range allowedCmd.Args.Allowed {
				if matched, e := regexp.MatchString(allowedRegex, originalArgs); e == nil {
					found = matched
				} else {
					writeLog("Unable to compile regex %s, got %s", allowedRegex, e.Error())
				}
			}
			if !found {
				return deny(fmt.Errorf("command `%s` arguments : `%s` not allowed", allowedCmd.Command, originalArgs))
			}
		}
		for search, replace := range allowedCmd.Args.Replace {
			if re, e := regexp.Compile(search); e == nil {
				originalArgs = re.ReplaceAllString(originalArgs, replace)
			} else {
				writeLog("Unable to compile regex %s, got %s", search, e.Error())
			}
		}
	}
	if config.Expand_env_vars != nil && *config.Expand_env_vars {
		originalArgs = os.ExpandEnv(originalArgs)
	}
	var cmd *exec.Cmd
	if config.Use_shell != "" {
		if config.Use_shell == "default" {
			if shell, ok := os.LookupEnv("SHELL"); ok {
				config.Use_shell = shell
			}
		}
		if shellPath, err := exec.LookPath(config.Use_shell); err == nil {
			cmd = exec.Command(shellPath, "-c", allowedCmd.Command+" "+originalArgs)
		} else {
			return deny(fmt.Errorf("did not found shell `%s` in path : `%s`", config.Use_shell, err.Error()))
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
	if len(config.cmd_tags) > 0 {
		logTags = fmt.Sprint(" tags `", strings.Join(config.cmd_tags, ","), "`")
	}
	writeLog("RUNNING - user `%s`%s command `%s`", user.Username, logTags, cmd.String())
	out, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), string(out)
		} else {
			return 1, string(out)
		}
	}
	return 0, string(out)
}

func writeLog(msg string, args ...interface{}) {
	if config.Enable_logging != nil && *config.Enable_logging {
		logger.Printf(msg, args...)
	}
}

// From https://stackoverflow.com/questions/34118732/parse-a-command-line-string-into-flags-and-arguments-in-golang
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
