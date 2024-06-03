import schedule
import asyncio

from log.log import CustomLogger
logger  = CustomLogger(__name__).get_logger()

class ScheduledTask:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, task_func=None, interval=None, unit=None,spesice_time=None):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self.task_func = task_func
            self.interval = interval
            self.unit = unit
            self.spesice_time = spesice_time
            
    async def run_async(self):
        if self.task_func:
            await self.task_func()
        else:
            raise ValueError("Task function not provided")

    async def run_schedule(self):
        job = getattr(schedule.every(self.interval), self.unit)
        if self.spesice_time:
            job.at(self.spesice_time).do(lambda: asyncio.ensure_future(self.run_async()))
            logger.warning(f"任务开始,执行时间：{job.next_run}")
        else:
            job.do(lambda: asyncio.ensure_future(self.run_async()))
        while True:
            schedule.run_pending()
            await asyncio.sleep(1)