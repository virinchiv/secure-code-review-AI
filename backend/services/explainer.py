from openai import OpenAI
import os
import requests
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.core.credentials import AzureKeyCredential
load_dotenv()


token = os.environ["API_KEY"]
endpoint = "https://models.github.ai/inference"
model = "openai/gpt-4.1"

client = ChatCompletionsClient(
    endpoint=endpoint,
    credential=AzureKeyCredential(token),
)

def explain_vulnerabilities(vuln_reports):
    explanations = []
    for vuln in vuln_reports:
        prompt = f"""Here is a piece of code:
        {vuln['code']}
        Detected vulnerability: {vuln['type']}
        You are a cybersecurity expert that explains every vulnerability in source code simply and precisely. 
        Explain why this is a security problem and rewrite the code or provide alternative using a secure approach. Only include relevant parts of the fix.
        """

        try:
            response = client.complete(
                messages=[
                    SystemMessage("You are a security assistant."),
                    UserMessage(prompt.strip())
                ],
                temperature=0.7,
                top_p=0.9,
                model=model
            )
            explanation = response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error generating explanation: {e}")
            explanation = ""

        explanations.append({
            "type": vuln["type"],
            "line": vuln["line"],
            "code": vuln["code"],
            "explanation": explanation.strip()
        })
    
    return explanations