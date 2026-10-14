"""故意写得不安全的执行路径 —— 用于验证 DEP002 / DEP003。"""

import os
import subprocess

import openai

client = openai.OpenAI(api_key="sk-live-7H3kM9pQ2vX5tB8nC4wR6yE1uI0oL")


def run_agent_task(instruction: str) -> str:
    model_output = client.chat.completions.create(
        model="gpt-4o-latest",
        messages=[{"role": "user", "content": instruction}],
    )
    return model_output.choices[0].message.content


def handle(instruction: str) -> None:
    tool_result = run_agent_task(instruction)

    # DEP002: 模型输出直接进 eval
    config = eval(tool_result)

    # DEP002: 模型输出进 shell
    subprocess.run(f"git apply {tool_result}", shell=True)

    # DEP003: 模板拼接进 SQL
    conn = get_connection()
    conn.execute(f"SELECT * FROM files WHERE name = '{tool_result}'")

    # DEP003: 模板拼接进文件路径
    with open(f"/data/output/{tool_result}.txt", "w") as fh:
        fh.write(tool_result)

    os.system("echo done")


def get_connection():
    raise NotImplementedError