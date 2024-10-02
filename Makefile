all:

test:
	poetry run pytest --ruff --ruff-format --cov

reformat:
	poetry run ruff check --select I --fix src tests
	poetry run ruff format src tests
