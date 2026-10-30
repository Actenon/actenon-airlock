FROM actenon-airlock-compute:dev
# Unchanged upstream agent; every archive hash is locked in requirements.txt.
COPY acceptance/v2/requirements.txt /opt/airlock/requirements.txt
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r /opt/airlock/requirements.txt
RUN python -m pip freeze > /opt/airlock/installed.txt
