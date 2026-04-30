from anthropic import Anthropic

def test_claude_key(api_key):
    try:
        client = Anthropic(api_key=api_key)

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=10,
            messages=[{"role": "user", "content": "ping"}]
        )

        return True, response.content[0].text

    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    key = input("Enter API key: ").strip()

    valid, result = test_claude_key(key)

    if valid:
        print("[+] VALID KEY")
        print("Response:", result)
    else:
        print("[-] INVALID KEY")
        print("Error:", result)