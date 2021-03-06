package main

import (
	"os"
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
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			want:       "Denied : direct ssh not allowed, you must specify a command",
			exitCode:   1,
		},
		{
			name:       "forbidden command",
			command:    "rm",
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			want:       "Denied : command `rm` not allowed",
			exitCode:   1,
		},
		{
			name:       "working command",
			command:    "/bin/echo test",
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			want:       "test",
			exitCode:   0,
		},
		{
			name:       "working command with some args",
			command:    "echo -e -n test",
			mainArgs:   []string{"test2"},
			configFile: "tests/authcmd_test.yml",
			want:       "test",
			exitCode:   0,
		},
		{
			name:       "just to be sure...",
			command:    "echo test ; rm mycriticalfile",
			mainArgs:   []string{"test2"},
			configFile: "tests/authcmd_test.yml",
			want:       "test ; rm mycriticalfile",
			exitCode:   0,
		},
		{
			name:       "terse output",
			command:    "chmod test",
			mainArgs:   []string{"test2"},
			configFile: "tests/authcmd_test.yml",
			want:       "Denied",
			exitCode:   1,
		},
		{
			name:       "allowed cmd output",
			command:    "echo test",
			mainArgs:   []string{"test3"},
			configFile: "tests/authcmd_test.yml",
			want:       "Allowed : ls,id",
			exitCode:   1,
		},
		{
			name:       "exit code",
			command:    "ls -l /doesnotexists",
			configFile: "tests/authcmd_test.yml",
			wantRegex:  "ls: .*doesnotexists.*",
			exitCode:   2,
		},
		{
			name:       "forbidden arg",
			command:    "/bin/echo iwant $MY_SECRET",
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			want:       "Denied : command `/bin/echo` argument : `$MY_SECRET` forbidden : regex `\\$`",
			exitCode:   1,
		},
		{
			name:       "allowed arg",
			command:    "ls -l authcmd.go",
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			wantRegex:  ".*authcmd.go.*",
			exitCode:   0,
		},
		{
			name:       "replace arg",
			command:    "/bin/echo I love pizza and pizza",
			mainArgs:   []string{"test1"},
			configFile: "tests/authcmd_test.yml",
			want:       "We love pizza and pasta",
			exitCode:   0,
		},
		{
			name:       "help text",
			command:    "notallowed",
			mainArgs:   []string{"test4"},
			configFile: "tests/authcmd_test.yml",
			want:       "This is a helping text",
			exitCode:   1,
		},
		{
			name:       "test expand",
			command:    "echo $PATH",
			mainArgs:   []string{"test5"},
			configFile: "tests/authcmd_test.yml",
			wantRegex:  ".*/bin.*",
			exitCode:   0,
		},
		{
			name:       "test no expand",
			command:    "echo $PATH",
			mainArgs:   []string{"test4"},
			configFile: "tests/authcmd_test.yml",
			want:       "$PATH",
			exitCode:   0,
		},
		{
			name:       "logging + double merging",
			command:    "echo test",
			mainArgs:   []string{"test5", "test6"},
			configFile: "tests/authcmd_test.yml",
			want:       "test",
			exitCode:   0,
		},
		{
			name:       "shell",
			command:    `echo "shell is : $0"`,
			mainArgs:   []string{"test5", "test7"},
			configFile: "tests/authcmd_test.yml",
			wantRegex:  "shell is : .*/sh",
			exitCode:   0,
		},
		{
			name:       "key_tag merging",
			command:    "id",
			configFile: "tests/authcmd_test.yml",
			mainArgs:   []string{"test8"},
			wantRegex:  ".*uid=.*",
			exitCode:   0,
		},
		{
			name:       "key_tag no merging",
			command:    "id",
			configFile: "tests/authcmd_test.yml",
			mainArgs:   []string{"doesnotexists"},
			want:       "Denied : command `id` not allowed",
			exitCode:   1,
		},
		{
			name:       "must match ko",
			command:    "cat /etc/passwd",
			configFile: "tests/authcmd_test.yml",
			mainArgs:   []string{"test9"},
			want:       "Denied : command `cat` arguments : ` /etc/passwd` not matching regex `.*LICENSE$`",
			exitCode:   1,
		},
		{
			name:       "must match ok",
			command:    "cat LICENSE",
			configFile: "tests/authcmd_test.yml",
			mainArgs:   []string{"test9"},
			wantRegex:  "^MIT License",
			exitCode:   0,
		},
		{
			name:       "no env var",
			command:    "echo x$MY_VAR",
			mainArgs:   []string{"test5"},
			configFile: "tests/authcmd_test.yml",
			want:       "x",
			exitCode:   0,
		},
		{
			name:       "command env var",
			command:    "echo $MY_VAR",
			mainArgs:   []string{"test10"},
			configFile: "tests/authcmd_test.yml",
			want:       "test10 echo cmd",
			exitCode:   0,
		},
		{
			name:       "global env var",
			command:    "echo $MY_VAR",
			mainArgs:   []string{"test11"},
			configFile: "tests/authcmd_test.yml",
			want:       "test11 global",
			exitCode:   0,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("SSH_ORIGINAL_COMMAND", tc.command)
			os.Setenv("AUTHCMD_CONFIG_FILE", tc.configFile)
			os.Args = append(os.Args[:1], tc.mainArgs...)
			exitCode, out := handle()
			//fmt.Println("out:", string(out))
			if exitCode != tc.exitCode {
				t.Errorf("Want exit code '%d', got '%d' with command '%s'", tc.exitCode, exitCode, tc.command)
			}
			if tc.wantRegex != "" {
				re, _ := regexp.Compile(tc.wantRegex)
				if !re.MatchString(out) {
					t.Errorf("Regex '%s' not matching, got '%s'", tc.wantRegex, out)
				}
			} else if strings.TrimSpace(string(out)) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, out)
			}
		})
	}
}
