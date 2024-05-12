import asyncio
from concurrent import futures

class AsyncAny(object):
    _instance = None
    
    def __new__(cls, *args, **kw):
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kw)
        return cls._instance

    def __init__(self, max_workers=5):
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers)

    def set_max_workers(self, max_workers=5):
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers)

    def trans_args(self, func, dict_arg):
        return func(*dict_arg['args'], **dict_arg['kwargs'])

    async def async_func(self, func, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.executor, self.trans_args,
            func, {'args': args, 'kwargs': kwargs}
        )

    async def do(self, func, *args, **kwargs):
        return (await asyncio.gather(self.async_func(func, *args, **kwargs)))[0]

async_func = AsyncAny().do

class Aobject(object):
    """Inheriting this class allows you to define an async __init__.

    So you can create objects by doing something like `await MyClass(params)`
    """
    async def __new__(cls, *a, **kw):
        instance = super().__new__(cls)
        await instance.__init__(*a, **kw)
        return instance

    async def __init__(self):
        pass