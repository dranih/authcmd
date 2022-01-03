# authcmd

[![Build Status](https://github.com/dranih/authcmd/workflows/Build%20and%20test/badge.svg)](https://github.com/dranih/authcmd/actions?workflow=Build%20and%20test)
[![coverage](https://codecov.io/gh/dranih/authcmd/branch/main/graph/badge.svg)](https://codecov.io/gh/dranih/authcmd)
[![report card](https://goreportcard.com/badge/github.com/dranih/authcmd)](https://goreportcard.com/report/github.com/dranih/authcmd)

This is an attempt to port the 'only' script from [MagmaSoft](https://at.magma-soft.at/sw/blog/posts/The_Only_Way_For_SSH_Forced_Commands).
The goal is to provide a way to control ssh access to a environnement with allowed/forbidden commands/arguments and replace.

The idea is to use the **command** parameter of the [**authorized_keys**](http://man.he.net/man5/authorized_keys) file which force the execution of a command when logging with a certain key.

**authcmd** still need tests and is not ready for any kind of serious usage.

*Any contribution is welcome*

## Usage
- Clone and compile authcmd :
```
github.com/dranih/authcmd
go build
```
- Put the **authcmd** binary in the PATH of the server to which the clients will ssh
- Configure the option file **authcmd.yml** with the allowed/forbidden commands/arguments and set env var **AUTHCMD_CONFIG_FILE** to it location or put it in your $HOME
  
- Add a line to the **~/.ssh.authorized_keys** :
```
command="authcmd <tag1> <tag2>" ssh-rsa AAAAB3N....
```

## Configuration

## Dependencies
- gopkg.in/yaml.v3 to parse yaml config file

## To-do
- [ ] Sanitize command if using shell, multi-command option (; delimiter, each command is checked)
- [ ] More tests
- [ ] Better readme (add some use cases)
- [X] Comment code
- [X] Add a github pipeline for testing and building
- [ ] Add a log rotate mecanism
- [X] Add a validation regex string option for each commands
- [X] Add an option to set an env variable (for exemple set different env vars depending on clients)
- [X] Add a way to distinct clients (maybe remove commands as main args and only take on client arg). This way we could allow/disallow commands to specific users