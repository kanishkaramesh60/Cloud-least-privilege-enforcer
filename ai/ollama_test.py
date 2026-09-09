import ollama

MODEL = "llama3.2:3b"

response = ollama.chat(
    model=MODEL,
    messages=[
        {
            "role": "user",
            "content": "Explain AWS IAM least privilege in one sentence."
        }
    ]
)

print("\nOLLAMA RESPONSE")
print("=" * 50)
print(response["message"]["content"])