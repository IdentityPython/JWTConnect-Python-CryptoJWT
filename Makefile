all:

test:
	uv run pytest --ruff --ruff-format --cov

reformat:
	uv run ruff check --select I --fix src tests
	uv run ruff format src tests
