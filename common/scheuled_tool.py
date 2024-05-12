import schedule
import asyncio

class ScheduledTask:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, task_func=None, interval=None, unit=None,  async_task=False):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self.task_func = task_func
            self.interval = interval
            self.unit = unit
            self.async_task = async_task
            
    async def run_async(self):
        if self.task_func:
            await self.task_func()
        else:
            raise ValueError("Task function not provided")

    async def run_schedule(self):
        job = getattr(schedule.every(self.interval), self.unit)
        job.do(lambda: asyncio.ensure_future(self.run_async()))
        while True:
            schedule.run_pending()
            await asyncio.sleep(1)

if __name__ == "__main__":
    def job():
        print("Job executed")

    async def async_job():
        job()

    a = ScheduledTask(task_func=async_job,interval=1,unit="seconds",async_task=True)
    asyncio.run(a.run_schedule())