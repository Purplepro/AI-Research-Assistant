import ollama
from langchain_ollama import ChatOllama
from langchain_tavily import TavilySearch
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent
import os

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")


# create agent
memory = MemorySaver()
model = ChatOllama(model="Qwen2.5:1.5b")
search = TavilySearch(max_results=2, tavily_api_key=TAVILY_API_KEY)
tools = [search]
agent_executor = create_react_agent(model, tools, checkpointer=memory)

config = {"configurable": {"thread_id": "abc123"}}

input_message = {
    "role": "user",
    "content": "What is the daily wather forecast like in SF?",
    }

for step in agent_executor.stream(
    {"messages": [input_message]}, config, stream_mode="values"
):
    step["messages"][-1].pretty_print()