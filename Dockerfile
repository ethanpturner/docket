# A pinned, dependency-free image. docket has no runtime dependencies, so the image is the
# interpreter and the package; there is nothing to resolve at build time and nothing to drift.
FROM python:3.14-slim

# uv installs the package and its console script without a virtual environment to activate.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN uv pip install --system --no-cache .

# The worktree under review is mounted, never copied: a finding set is about somebody else's code.
WORKDIR /work
ENTRYPOINT ["docket"]
CMD ["--help"]
