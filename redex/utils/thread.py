import threading
import os
from multiprocessing.pool import ThreadPool
from typing import List, Any, Callable
from rich.progress import Progress


class Threading(object):
    @staticmethod
    def threadpool_executor(
        function: Callable, iterable: List[Any], iterable_len: int
    ) -> None:
        number_of_workers = os.cpu_count()
        with ThreadPool(number_of_workers) as pool, Progress() as prog:
            scan = prog.add_task("Progress", total=iterable_len)
            for loop_index, _ in enumerate(pool.imap(function, iterable), 1):
                prog.update(scan, advance=1.0)
    
    @staticmethod
    def run_single_thread(
        function: Callable, daemon: bool=True, *args
    ) -> threading.Thread:
        t = threading.Thread(target=function, args=args, daemon=daemon)
        t.start()
        return t