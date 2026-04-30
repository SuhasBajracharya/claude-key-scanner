from openai import OpenAI

def test_openai_key(api_key):
    try:
        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5
        )

        return True, response.choices[0].message.content

    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    key = input("Enter OpenAI API key: ").strip()

    valid, result = test_openai_key(key)

    if valid:
        print("[+] VALID KEY")
        print("Response:", result)
    else:
        print("[-] INVALID / ERROR")
        print("Error:", result)