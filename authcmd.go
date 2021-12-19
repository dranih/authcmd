package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Show_terse_denied bool
	Show_allowed      bool
	Show_denied       bool
	Expand_env_vars   bool
	Enable_logging    bool
	Log_file          string
	Use_shell         string
	Help_text         string
	Allowed_cmd       []*cmd
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
		return deny(err)
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

	if config.Enable_logging {
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
			config.Enable_logging = false
		} else {
			logger.SetOutput(logFile)
			logger.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
		}
	}

	// Adding command args to config args
	for _, allowed := range os.Args[1:] {
		found := false
		for _, existingCmd := range config.Allowed_cmd {
			if existingCmd.Command == allowed {
				found = true
			}
		}
		if !found {
			config.Allowed_cmd = append(config.Allowed_cmd, &cmd{Command: allowed})
		}
	}
	return nil
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
	user, _ := user.Current()
	writeLog("WARN - Denied user `%s` with error `%s`", user.Username, err.Error())
	var out string
	if config.Show_terse_denied {
		out = "Denied\n"
	} else {
		if config.Show_denied {
			out = fmt.Sprintf("Denied : %s\n", err.Error())
		}
		if config.Show_allowed {
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
	if config.Expand_env_vars {
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
	writeLog("RUNNING - user `%s` command `%s`", user.Username, cmd.String())
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
	if config.Enable_logging {
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
