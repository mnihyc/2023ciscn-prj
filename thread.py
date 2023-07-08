import time, functools
from typing import TypeVar, Generic, Callable, Iterable
from collections import deque
from threading import Thread, Condition

T = TypeVar('T')

class ItemPool(Generic[T]):
    _IKS: deque[T]
    _lock: Condition

    def __init__(self):
        self._IKS = deque()
        self._lock = Condition()
    
    @staticmethod
    def wrap_lock(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            with self._lock:
                return func(self, *args, **kwargs)
        return wrapper

    @wrap_lock
    def add(self, item: T):
        self._IKS.append(item)
        self._lock.notify()
    
    @wrap_lock
    def pop(self) -> T|None:
        if len(self._IKS) == 0:
            return None
        return self._IKS.popleft()
    
    @wrap_lock
    def pop_block(self, timeout: float|None = None) -> T|None:
        if len(self._IKS) == 0:
            self._lock.wait(timeout)
            if len(self._IKS) == 0:
                return None
        return self._IKS.popleft()

    @wrap_lock
    def front(self) -> T|None:
        if len(self._IKS) == 0:
            return None
        return self._IKS[0]
    
    @wrap_lock
    def clear(self):
        self._IKS.clear()

    @wrap_lock
    def mark_for_end(self):
        self._lock.notify_all() # clear all waiting threads

    @property
    @wrap_lock
    def length(self) -> int:
        return len(self._IKS)
    
    @property
    def data(self) -> deque[T]: # lock before use
        return self._IKS


class ThreadPool:
    task: ItemPool
    WKS: list[Thread]

    def worker(self):
        while (task := self.task.pop_block()) is not None:
            task()
    
    def __init__(self, size: int):
        self._size = size
        self.task = ItemPool[Callable[..., None]]()
        self.WKS = [Thread(target=self.worker) for _ in range(size)]
    
    @property
    def size(self) -> int:
        return self._size
        
    def start(self):
        for wk in self.WKS:
            if self.task.length == 0:
                break
            wk.start()

    def kill(self):
        self.task.clear()
        self.join()
    
    def join(self):
        while not self.finished():
            time.sleep(3)
            self.task.mark_for_end()
    
    def finished(self) -> bool:
        for wk in self.WKS:
            if wk.is_alive():
                return False
        return True
    