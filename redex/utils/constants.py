APP_NAME = """

   ▄████████    ▄████████ ████████▄     ▄████████ ▀████    ▐████▀ 
  ███    ███   ███    ███ ███   ▀███   ███    ███   ███▌   ████▀  
  ███    ███   ███    █▀  ███    ███   ███    █▀     ███  ▐███    
 ▄███▄▄▄▄██▀  ▄███▄▄▄     ███    ███  ▄███▄▄▄        ▀███▄███▀    
▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███    ███ ▀▀███▀▀▀        ████▀██▄     
▀███████████   ███    █▄  ███    ███   ███    █▄    ▐███  ▀███    
  ███    ███   ███    ███ ███   ▄███   ███    ███  ▄███     ███▄  
  ███    ███   ██████████ ████████▀    ██████████ ████       ███▄ 
  ███    ███                                                      

"""

INFO = """
[green]##############################################[/green]
[green]####[/green] [bold red]A Simple Docker Engine API Exploiter[/bold red] [green]####[/green]
[green]##############################################[/green]
"""

BUGS = []

## ------------------------------ DOCUMENTATION COMMANDS CONTSANTS ------------------------------
C_HELP_NAME = "help"
C_HELP_CMD  = "help [COMMAND1 ...]"
C_HELP_DESC = "Shows the description of one or more commands. All if none is given"
# ------------------------------------------------------------
C_CLEAR_NAME = "clear"
C_CLEAR_CMD  = "clear"
C_CLEAR_DESC = "Clear the Command-Line Interface"
# ------------------------------------------------------------
C_QUIT_NAME = "quit"
C_QUIT_CMD  = "quit" 
C_QUIT_DESC = "Quit the application. It is activated also with CTRL + C"
# ------------------------------------------------------------
C_SET_NAME = "set"
C_SET_CMD  = "set VAR=VALUE"
C_SET_DESC = "Set the value of a session variable. To see all possible variables type 'show'"
# ------------------------------------------------------------
C_SETDATA_NAME = "setdata"
C_SETDATA_CMD  = "setdata VAR=JSONFILE"
C_SETDATA_DESC = "Set the value of a container data variable with the content of a JSON file"
# ------------------------------------------------------------
C_SHOW_NAME = "show"
C_SHOW_CMD  = "show [VAR1 ...]"
C_SHOW_DESC = "Show the value of a session variable. All if no input is given"
# ------------------------------------------------------------
C_SHOWDATA_NAME = "showdata"
C_SHOWDATA_CMD  = "showdata [VAR1 ...]"
C_SHOWDATA_DESC = """Shows the content of a container data variable 'VAR'.
    If no name is provided, then all variables will be listed.
"""
# ------------------------------------------------------------
C_SCAN_NAME = "scan"
C_SCAN_CMD  = "scan [IP]"
C_SCAN_DESC = """Scan a specified 'IP' looking for open ports. If no input is provided
    it will scan the IP provided in the session variable 'RHOST'.
"""
# ------------------------------------------------------------
C_LSTIMGS_NAME = "lstimgs"
C_LSTIMGS_CMD  = "lstimgs [filters=[IMAGE1[:TAG1] ...]]"
C_LSTIMGS_DESC = "List all images of a remote host, or those that match the filters"
# ------------------------------------------------------------
C_PULL_NAME = "pull"
C_PULL_CMD  = "pull [IMAGE[:TAG]]"
C_PULL_DESC = """Pull a given image on the remote host. If no input is provided
    it will pull the one provided by the value of the session variable 'IMAGE'.
    To see the content of this variable type 'show image'
"""
# ------------------------------------------------------------
C_CREATE_NAME = "create"
C_CREATE_CMD  = "create [NAME] [DATA=DATA]"
C_CREATE_DESC = """Create a container in a remote host. The DATA argument selects 
    the corresponding container data variable that contains the settings of the 
    new container. If no data is provided, it will use the one of the DEFAULT 
    variable. Type 'showdata DEFAULT' to see the content of this variable. Also, 
    you can type 'showdata' to see the content of all container data variables. 
    The name of the new container will be setted either to the value of the NAME 
    argument, if provided, or to the value of the 'NAME' session variable. If a 
    different name is provided then it will be added to the set of all names. To 
    show the content of the 'NAME' variable type 'show name', otherwise to see all 
    names type 'shownames'.
"""
# ------------------------------------------------------------
C_START_NAME = "start"
C_START_CMD  = "start [NAME]"
C_START_DESC = """Start a container with name 'NAME'. If no input is provided
    it will start the one named by the session variable 'NAME'. To see the content
    of this variable just type 'show name'.
"""
# ------------------------------------------------------------
C_STOP_NAME = "stop"
C_STOP_CMD  = "stop [NAME]"
C_STOP_DESC = """Stop a running container named 'NAME'. If no input is provided
    it will stop the one named by the session variable 'NAME'. To see the content
    of this variable just type 'show name'.
"""
# ------------------------------------------------------------
C_LSTCONTS_NAME = "lstconts"
C_LSTCONTS_CMD  = "lstconts [all] [imgs=[IMG1,...]] [nets=[NET1,...]] [status=[STATUS,...]]"
C_LSTCONTS_DESC = """List some or all containers in a remote host.
    By default, only running containers will be listed. However,
    it is possible to change this behaviour by using the 'all' flag.
    It is also possible to filter out some containers that we don't
    want to see in the final result. This can be done by setting
    precise values to 'imgs', 'nets' and 'status' input arguments.
    In particular:
        - 'imgs' filters containers by given images
        - 'nets' filters containers by given networks
        - 'status' filters containers by a given status. 
          Possible status are:
            + [italic]created[/italic]
            + [italic]restarting[/italic]
            + [italic]running[/italic]
            + [italic]removing[/italic]
            + [italic]paused[/italic]
            + [italic]exited[/italic]
            + [italic]dead[/italic]
"""
# ------------------------------------------------------------