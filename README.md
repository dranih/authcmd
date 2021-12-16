# authcmd

This is an attempt to port the 'only' script from [MagmaSoft](https://at.magma-soft.at/sw/blog/posts/The_Only_Way_For_SSH_Forced_Commands)
The goal is to provide a way to control ssh access to a environnement with allowed/forbidden commands/arguments and replace.

The idea is to use the **command** parameter of the **authorized_keys** file which force the execution of a command when logging with a certain key.

**authcmd** still need tests and is not ready for any kind of serious usage.

*Any contribution welcomed*

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
command="authcmd" 
```

## To-do
- [ ] More tests (and find a way to get coverage)
- [ ] Better readme (add some use cases)
- [ ] Comment code
- [ ] Add a github pipeline for testing and building