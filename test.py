import google.generativeai as genai

# Configure your API key
genai.configure(api_key="AIzaSyBRZ0KEt_vYCyOsH71lci6xXvlArk0MgzU")

# Stream the response as it is being generated
response = genai.stream_generate_text(
    model="gemini-2.0-flash",
    prompt="Explain how AI works"
)

# Process and print each chunk of the streamed response
for chunk in response:
    print(chunk, end="")
