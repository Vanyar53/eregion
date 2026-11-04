"""OL1 (#525): H0 requires only the key of the configured model's provider — eregion_core/models.py
defines the rule (required_env), infra/glorfindel-host/host_env.py applies it to host.env and to
`--check`. M3655–M3659, measured by tests/unit/test_glorfindel_host.py."""
HOST_ENV = "infra/glorfindel-host/host_env.py"
MODELS = "eregion_core/models.py"
_HOST = "tests/unit/test_glorfindel_host.py::"
_ONLY = f"{_HOST}test_host_env_requires_only_the_key_of_the_models_provider"
_UNKNOWN = f"{_HOST}test_host_env_refuses_an_unknown_provider_with_the_list_never_the_value"

MUTANTS = [
    ("M3655", "ANTHROPIC_API_KEY required whatever the model, even a local one (#525, OL1)", HOST_ENV,
     'REQUIRED = ("AZURE_SUBSCRIPTION_ID",)',
     'REQUIRED = ("AZURE_SUBSCRIPTION_ID", "ANTHROPIC_API_KEY")'),
    ("M3656", "a local model (Ollama) without its address: the watch calls its own container (OL1)",
     MODELS,
     "        return () if base_url else (BASE_URL,)\n",
     "        return ()\n"),
    ("M3657", "an unknown provider taken for Anthropic's, its own key never asked (OL1)", MODELS,
     "    if sep and rest and provider in PROVIDER_ENV:\n        return provider\n",
     "    if sep and rest and provider in PROVIDER_ENV:\n        return provider\n"
     '    return "anthropic"\n'),
    ("M3658", "the refusal repeats the model's value: a key pasted in the wrong variable printed (OL1)",
     MODELS,
     '        "the model names no known provider',
     '        f"the model ({name}) names no known provider'),
    ("M3659", "`--check` pushes a host.env without its model's key: the watch could not decide (OL1)",
     HOST_ENV,
     "    provider, lacking = model_missing(env)\n    if lacking:\n        raise SystemExit(f\"{dst}: ",
     "    provider, lacking = model_missing(env)\n    if False:\n        raise SystemExit(f\"{dst}: "),
]
TESTS = {
    "M3655": _ONLY,
    "M3656": _ONLY,
    "M3657": _UNKNOWN,
    "M3658": _UNKNOWN,
    "M3659": f"{_HOST}test_check_holds_a_host_env_to_the_models_provider",
}
