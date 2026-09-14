"""Provider presets.

Every provider here speaks the OpenAI wire format, so the gateway forwards
requests unchanged and only the base URL, auth style and default model differ.
Anthropic and Google's native APIs use a different request shape and are not
included; use their OpenAI-compatible endpoints, or Custom.
"""

PROVIDERS = {
    "openai": {
        "label": "OpenAI",
        "url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "auth": "bearer",
        "note": "",
    },
    "azure_openai": {
        "label": "Azure OpenAI",
        "url": "https://YOUR-RESOURCE.openai.azure.com/openai/v1",
        "model": "",
        "auth": "api-key",
        "note": "Use your deployment name as the model.",
    },
    "openrouter": {
        "label": "OpenRouter",
        "url": "https://openrouter.ai/api/v1",
        "model": "openai/gpt-4o-mini",
        "auth": "bearer",
        "note": "Models are namespaced provider/model.",
    },
    "groq": {
        "label": "Groq",
        "url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "auth": "bearer",
        "note": "",
    },
    "mistral": {
        "label": "Mistral",
        "url": "https://api.mistral.ai/v1",
        "model": "mistral-small-latest",
        "auth": "bearer",
        "note": "",
    },
    "deepseek": {
        "label": "DeepSeek",
        "url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "auth": "bearer",
        "note": "",
    },
    "together": {
        "label": "Together AI",
        "url": "https://api.together.xyz/v1",
        "model": "",
        "auth": "bearer",
        "note": "",
    },
    "cerebras": {
        "label": "Cerebras",
        "url": "https://api.cerebras.ai/v1",
        "model": "llama3.1-8b",
        "auth": "bearer",
        "note": "",
    },
    "google": {
        "label": "Google AI Studio",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.0-flash",
        "auth": "bearer",
        "note": "OpenAI-compatible surface, not the native Gemini API.",
    },
    "anthropic": {
        "label": "Anthropic",
        "url": "https://api.anthropic.com/v1",
        "model": "claude-sonnet-4-5",
        "auth": "x-api-key",
        "note": "Native API is not OpenAI-shaped. Clients must speak it directly.",
    },
    "ollama": {
        "label": "Ollama (local)",
        "url": "http://ollama:11434/v1",
        "model": "qwen2.5:7b-instruct",
        "auth": "none",
        "note": "Nothing leaves the machine.",
    },
    "vllm": {
        "label": "vLLM / LM Studio",
        "url": "http://localhost:8000/v1",
        "model": "",
        "auth": "none",
        "note": "Any self-hosted OpenAI-compatible server.",
    },
    "freellmapi": {
        "label": "FreeLLMAPI router",
        "url": "http://freellmapi-1:3001/v1",
        "model": "auto:fast",
        "auth": "bearer",
        "note": "Aggregates several free tiers behind one endpoint.",
    },
    "custom": {
        "label": "Custom",
        "url": "",
        "model": "",
        "auth": "bearer",
        "note": "Any other OpenAI-compatible endpoint.",
    },
}


def auth_headers(provider_type: str, token: str) -> dict:
    """Auth header for a provider. Bearer covers almost everything."""
    style = PROVIDERS.get(provider_type, PROVIDERS["custom"])["auth"]
    if not token:
        return {}
    if style == "api-key":
        return {"api-key": token}
    if style == "x-api-key":
        # Anthropic also wants a version header on every request.
        return {"x-api-key": token, "anthropic-version": "2023-06-01"}
    if style == "none":
        return {}
    return {"Authorization": f"Bearer {token}"}


def catalogue() -> list:
    return [{"key": k, **v} for k, v in PROVIDERS.items()]
