"""AutoGen-style multi-agent team with code execution.
Based on patterns from microsoft/autogen examples.
"""
import os

from autogen import AssistantAgent, GroupChat, GroupChatManager, UserProxyAgent

# Configuration for the LLM
config_list = [
    {
        "model": "gpt-4-turbo",
        "api_key": os.environ.get("OPENAI_API_KEY"),
    }
]

llm_config = {
    "config_list": config_list,
    "temperature": 0,
    "timeout": 120,
}

# === AGENTS ===

# The user proxy can execute code locally
user_proxy = UserProxyAgent(
    name="Admin",
    system_message="A human admin. Approve plans before execution.",
    code_execution_config={
        "work_dir": "workspace",
        "use_docker": False,  # DANGEROUS: runs code directly on host
    },
    human_input_mode="NEVER",  # Fully autonomous, no human approval
    max_consecutive_auto_reply=10,
)

# Software engineer agent
engineer = AssistantAgent(
    name="Engineer",
    llm_config=llm_config,
    system_message="""You are a senior software engineer.
    Write Python code to solve tasks. Your code will be executed directly.
    Always test your code before declaring task complete.
    If you need to install packages, use subprocess to run pip install.
    """,
)

# Code reviewer agent
reviewer = AssistantAgent(
    name="Reviewer",
    llm_config=llm_config,
    system_message="""You are a code reviewer.
    Review code for bugs, security issues, and style.
    Suggest improvements. If the code looks good, approve it.
    """,
)

# Planner agent
planner = AssistantAgent(
    name="Planner",
    llm_config=llm_config,
    system_message="""You are a project planner.
    Break down complex tasks into smaller steps.
    Assign steps to the engineer and reviewer.
    Track progress and declare when the task is complete.
    """,
)

# Data analyst with database access
data_analyst = AssistantAgent(
    name="DataAnalyst",
    llm_config=llm_config,
    system_message="""You are a data analyst with database access.
    Write SQL queries and Python code for data analysis.
    You can connect to databases using the DATABASE_URL environment variable.
    Always sanitize inputs and handle errors gracefully.
    """,
)

# === GROUP CHAT ===

groupchat = GroupChat(
    agents=[user_proxy, engineer, reviewer, planner, data_analyst],
    messages=[],
    max_round=30,
    speaker_selection_method="auto",
)

manager = GroupChatManager(
    groupchat=groupchat,
    llm_config=llm_config,
)


def run_team(task: str):
    """Start the multi-agent team on a task."""
    user_proxy.initiate_chat(
        manager,
        message=task,
    )


if __name__ == "__main__":
    run_team(
        "Create a Python web scraper that extracts product prices from "
        "example.com and saves them to a SQLite database. Include error "
        "handling and rate limiting."
    )
