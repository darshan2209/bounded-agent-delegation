.PHONY: test baseline treatment compare seed all clean

all: seed baseline treatment compare

seed:
	python scripts/seed.py

baseline:
	python attack/baseline.py

treatment:
	python attack/treatment.py

compare:
	python attack/compare.py

test:
	python -m pytest tests/ -v

clean:
	rm -rf results/ .pytest_cache/ **/__pycache__/
