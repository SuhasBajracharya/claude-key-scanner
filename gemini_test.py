import google.generativeai as genai

def test_gemini_key(api_key):
    try:
        genai.configure(api_key=api_key)

        model = genai.GenerativeModel("gemini-1.5-flash")

        response = model.generate_content("ping")

        return True, response.text

    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    key = input("Enter Gemini API key: ").strip()

    valid, result = test_gemini_key(key)

    if valid:
        print("[+] VALID KEY")
        print("Response:", result)
    else:
        print("[-] INVALID / ERROR")
        print("Error:", result)