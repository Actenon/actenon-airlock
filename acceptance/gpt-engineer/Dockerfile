FROM actenon-airlock-compute:dev
COPY acceptance/gpt-engineer/requirements.txt /opt/airlock/requirements.txt
# The lock contains all transitive dependencies. Avoid a second full resolver;
# still verify every archive hash and the installed dependency relationships.
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r /opt/airlock/requirements.txt && python -m pip check
RUN mkdir -p /opt/airlock/tiktoken && TIKTOKEN_CACHE_DIR=/opt/airlock/tiktoken python -c "import tiktoken; tiktoken.get_encoding('cl100k_base'); tiktoken.get_encoding('o200k_base')"
RUN python -m pip freeze > /opt/airlock/installed.txt
