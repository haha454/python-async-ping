# Python Async Ping
`python-async-ping` is a lib that you can use to issue `ping`s to a remote server.

## Example usage

```python
from pinglib.ping import Ping

async def my_main():
    ping = Ping('www.google.com')
    async for response in ping.exec(times=4, interval_sec=0.5):
        print(response)

    print(ping)

asyncio.run(my_main()) 
```
