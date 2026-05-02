from huggingface_hub import InferenceClient

def test_key(api_key):
    try:
        client = InferenceClient(token=api_key)

        response = client.text_generation(
            "Ping",
            model="gpt2",
            max_new_tokens=5
        )

        return True, response.strip()

    except Exception as e:
        return False, str(e)


def main():
    print("Enter your Hugging Face API keys (one per line).")
    print("Type 'done' when finished:\n")

    keys = []

    while True:
        key = input("API Key: ").strip()
        if key.lower() == "done":
            break
        if key:
            keys.append(key)

    print("\n--- Testing Keys ---\n")

    for i, key in enumerate(keys, start=1):
        print(f"[{i}] Testing key: {key[:10]}...")

        success, result = test_key(key)

        if success:
            print("✅ VALID")
            print(f"Response: {result}\n")
        else:
            print("❌ INVALID")
            print(f"Error: {result}\n")


if __name__ == "__main__":
    main()