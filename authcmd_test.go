package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestAuthCmd(t *testing.T) {
	tt := []struct {
		name       string
		command    string
		mainArgs   []string
		configFile string
		want       string
		wantRegex  string
		exitCode   int
	}{
		{
			name:       "empty command",
			command:    "",
			configFile: "tests/authcmd_test1.yml",
			want:       "Denied : direct ssh not allowed, you must specify a command",
			exitCode:   1,
		},
		{
			name:       "forbidden command",
			command:    "rm",
			mainArgs:   []string{"ls"},
			configFile: "tests/authcmd_test1.yml",
			want:       "Denied : command `rm` not allowed",
			exitCode:   1,
		},
		{
			name:       "working command",
			command:    "echo test",
			configFile: "tests/authcmd_test1.yml",
			mainArgs:   []string{"echo"},
			want:       "test",
			exitCode:   0,
		},
		{
			name:       "working command with some args",
			command:    "echo -e -n test",
			configFile: "tests/authcmd_test2.yml",
			mainArgs:   []string{"echo"},
			want:       "test",
			exitCode:   0,
		},
		{
			name:       "just to be sure...",
			command:    "echo test ; rm mycriticalfile",
			configFile: "tests/authcmd_test2.yml",
			mainArgs:   []string{"echo"},
			want:       "test ; rm mycriticalfile",
			exitCode:   0,
		},
		{
			name:       "terse output",
			command:    "echo test",
			configFile: "tests/authcmd_test2.yml",
			want:       "Denied",
			exitCode:   1,
		},
		{
			name:       "allowed cmd output",
			command:    "echo test",
			mainArgs:   []string{"ls"},
			configFile: "tests/authcmd_test3.yml",
			want:       "Allowed : id,ls",
			exitCode:   1,
		},
		{
			name:       "exit code",
			command:    "ls /doesnotexists",
			mainArgs:   []string{"ls"},
			configFile: "tests/authcmd_test2.yml",
			want:       "",
			exitCode:   2,
		},
		{
			name:       "forbidden arg",
			command:    "/bin/echo iwant $MY_SECRET",
			configFile: "tests/authcmd_test1.yml",
			want:       "Denied : command `/bin/echo` arguments : `iwant $MY_SECRET` forbidden : regex `\\$`",
			exitCode:   1,
		},
		{
			name:       "allowed arg",
			command:    "ls -l authcmd.go",
			configFile: "tests/authcmd_test1.yml",
			wantRegex:  ".*authcmd.go.*",
			exitCode:   0,
		},
		{
			name:       "replace arg",
			command:    "/bin/echo I love pizza and pizza",
			configFile: "tests/authcmd_test1.yml",
			want:       "I love pizza and pasta",
			exitCode:   0,
		},
		{
			name:       "help text",
			command:    "notallowed",
			configFile: "tests/authcmd_test4.yml",
			want:       "This is a helping text",
			exitCode:   1,
		},
		{
			name:       "test expand",
			command:    "echo $PATH",
			configFile: "tests/authcmd_test5.yml",
			wantRegex:  ".*/bin.*",
			exitCode:   0,
		},
		{
			name:       "test no expand",
			command:    "echo $PATH",
			mainArgs:   []string{"echo"},
			configFile: "tests/authcmd_test4.yml",
			want:       "$PATH",
			exitCode:   0,
		},
	}
	if os.Getenv("FLAG") == "1" {
		//Shift args to remove -test.run...
		os.Args = os.Args[1:]
		main()
		return
	} else {
		for _, tc := range tt {
			t.Run(tc.name, func(t *testing.T) {
				// Run the test in a subprocess
				tc.mainArgs = append([]string{"-test.run=TestAuthCmd"}, tc.mainArgs...)
				cmd := exec.Command(os.Args[0], tc.mainArgs...)
				cmd.Env = append(os.Environ(), "FLAG=1")
				cmd.Env = append(cmd.Env, "SSH_ORIGINAL_COMMAND="+tc.command)
				cmd.Env = append(cmd.Env, "AUTHCMD_CONFIG_FILE="+tc.configFile)
				out, err := cmd.Output()

				// Cast the error as *exec.ExitError and compare the result
				e, ok := err.(*exec.ExitError)
				exitCode := 0
				if ok {
					exitCode = e.ExitCode()
				}
				if exitCode != tc.exitCode {
					t.Errorf("Want exit code '%d', got '%d' with command '%s'", tc.exitCode, exitCode, tc.command)
				}
				fmt.Println("out:", string(out))
				if tc.wantRegex != "" {
					re, _ := regexp.Compile(tc.wantRegex)
					if !re.Match(out) {
						t.Errorf("Regex '%s' not matching, got '%s'", tc.wantRegex, out)
					}
				} else if strings.TrimSpace(string(out)) != tc.want {
					t.Errorf("Want '%s', got '%s'", tc.want, out)
				}
			})
		}
	}
}
