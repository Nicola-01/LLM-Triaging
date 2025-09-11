# quick_llm_ping.py
import asyncio
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider

API_KEY = open("api.key").read().strip()  # same path you use

async def main():
    agent = Agent(GoogleModel("gemini-1.5-flash", provider=GoogleProvider(api_key=API_KEY)))
    async with agent:
        res = await agent.run("Say 'pong' only.")
    print(res.output)

asyncio.run(main())
