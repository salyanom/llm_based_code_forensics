import ollama

response = ollama.chat(
    model="deepseek-coder:6.7b",
    messages=[{"role": "user", "content": "Hello"}]
)

print(response["message"]["content"])