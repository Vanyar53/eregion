"""OL1 (#525): H0 requires only the key of the configured model's provider — eregion_core/models.py
defines the rule (required_env), infra/glorfindel-host/host_env.py applies it to host.env, to
`--check` and, through it, to `make glorfindel-host-model`. M3655–M3659 and M3680–M3684,
measured by tests/unit/test_glorfindel_host.py and tests/unit/test_host_console.py."""
HOST_ENV = "infra/glorfindel-host/host_env.py"
MODELS = "eregion_core/models.py"
MAKEFILE = "Makefile"
_HOST = "tests/unit/test_glorfindel_host.py::"
_COMPOSE = f"{_HOST}test_check_reads_the_models_variables_as_compose_gives_them_to_the_watch"
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
     "for k in (MODEL, BASE_URL, *MODEL_KEYS)})\n    if lacking:\n",
     "for k in (MODEL, BASE_URL, *MODEL_KEYS)})\n    if False:\n"),
    # After the review of 463897d9: M3680–M3684.
    ("M3680", "every provider's key of the .envrc copied to H0, and to the watch (OL1)", HOST_ENV,
     "if environ.get(k) and (k not in MODEL_KEYS or k in carried)}",
     "if environ.get(k)}"),
    ("M3681", "`make glorfindel-host-model` writes the new model with no check: H0 restarts "
     "without its key (OL1)", MAKEFILE,
     "\t $(PYTHON) infra/glorfindel-host/host_env.py --check $$c >/dev/null; rc=$$?; rm -f $$c; \\\n",
     "\t rc=0; rm -f $$c; \\\n"),
    ("M3682", "a local analysis model never said: every campaign report fails (OL1)", HOST_ENV,
     "    if provider in LOCAL_PROVIDERS:\n        return (f\"⚠ l'IA d'analyse",
     "    if False:\n        return (f\"⚠ l'IA d'analyse"),
    ("M3683", "a quoted model or key of host.env read with its quotes, unlike compose (OL1)",
     HOST_ENV,
     "    if len(v) >= 2 and v[0] == v[-1] and v[0] in \"\\\"'\":\n",
     "    if False:\n"),
    ("M3684", "a key of host.env that is only a comment taken for a key (OL1)", HOST_ENV,
     '    return "" if v.startswith("#") else v\n',
     "    return v\n"),
]
TESTS = {
    "M3655": _ONLY,
    "M3656": _ONLY,
    "M3657": _UNKNOWN,
    "M3658": _UNKNOWN,
    "M3659": f"{_HOST}test_check_holds_a_host_env_to_the_models_provider",
    "M3680": f"{_HOST}test_host_env_carries_no_other_providers_key",
    "M3681": "tests/unit/test_host_console.py -k model_change",
    "M3682": f"{_HOST}test_a_local_model_without_the_analysis_key_is_said_not_refused",
    "M3683": f"{_COMPOSE}",
    "M3684": f"{_COMPOSE}",
}
