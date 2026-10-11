# VEC flag server -- portable image.
#
# Stock python base only: no campaign code, no plugins, nothing to patch.
FROM python:3.12-alpine
WORKDIR /srv

# verifiers.py carries the per-challenge objective decisions. Without it in
# the image the /verify route 500s and no challenge can award a flag.
COPY flag_server.py verifiers.py phrases.py /srv/

RUN mkdir -p /state && adduser -D -u 10002 vec && chown -R vec /state /srv
USER vec

EXPOSE 8099
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10   CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8099/healthz')" || exit 1

# --state is passed explicitly, not left to the default. The default is
# /var/lib/vec, which the non-root user cannot create, so a plain
# `docker run` of this image died with PermissionError. /state is created
# above and owned by vec, so both `docker run` and compose work.
CMD ["python3", "-u", "flag_server.py", "--bind", "0.0.0.0", "--port", "8099", "--state", "/state"]
